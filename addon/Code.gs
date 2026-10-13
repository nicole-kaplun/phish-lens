/**
 * PhishLens - Gmail add-on.
 *
 * The add-on only collects what the backend needs and shows the result.
 * All detection logic and any API keys live in the backend, so nothing
 * sensitive is stored here (this file is public on GitHub).
 *
 * What leaves Gmail, to the PhishLens backend only:
 *   - From and Reply-To headers, Gmail's Authentication-Results headers
 *   - link targets and their visible text
 *   - attachment names, types, sizes and SHA-256 hashes (never contents)
 *   - the subject and the FIRST 1,500 CHARACTERS of the plain-text body
 * The backend forwards the subject and that excerpt to Gemini on Vertex AI
 * for wording analysis, except for DMARC-verified mail from known brands.
 * Text after the first 1,500 characters is never analysed.
 */

var LIMITS = {
  HEADER_CHARS: 4000,
  BODY_CHARS: 1500,
  LINKS: 100,
  HREF_CHARS: 2048,
  LINK_TEXT_CHARS: 500,
  ATTACHMENTS: 20,
  HASH_MAX_BYTES: 10 * 1024 * 1024,
};

// A result is reused for 10 minutes, so reopening a message is instant and
// does not spend VirusTotal or Gemini quota again.
var CACHE_SECONDS = 600;

var VERDICTS = {
  safe:       { label: 'Low risk',   color: '#188038', advice: 'No warning signs found in any check.' },
  suspicious: { label: 'Suspicious', color: '#E37400', advice: 'Check before you click links or open attachments.' },
  malicious:  { label: 'Malicious',  color: '#D93025', advice: 'Do not click links or open attachments. Report and delete.' },
};

/** Contextual trigger: Gmail calls this every time the user opens a message. */
function onGmailMessageOpen(e) {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    return buildResultCard_(analyzeWithCache_(e.gmail.messageId));
  } catch (err) {
    console.error(err);
    return buildErrorCard_();
  }
}

/**
 * Per-user cache (other users cannot read it), keyed by message ID.
 * Results where an outside check failed are not cached, so the next open
 * retries instead of repeating an incomplete answer for 10 minutes.
 */
function analyzeWithCache_(messageId) {
  var cache = CacheService.getUserCache();
  var key = 'analysis:v1:' + messageId;
  var hit = cache.get(key);
  if (hit) return JSON.parse(hit);

  var result = callBackend_(extractPayload_(GmailApp.getMessageById(messageId)));
  var transientFailure = (result.findings || []).some(function (f) {
    return f.points === 0 && /(check|analysis) unavailable/i.test(f.title);
  });
  if (!transientFailure) {
    try {
      cache.put(key, JSON.stringify(result), CACHE_SECONDS);
    } catch (err) {
      console.warn('result not cached: ' + err);  // e.g. larger than the 100 KB cache limit
    }
  }
  return result;
}

// ------------------------------------------------------------ extraction

/** Only what the checks need. The body is cut to its first 1,500 characters. */
function extractPayload_(message) {
  return {
    from_header: truncate_(message.getFrom(), LIMITS.HEADER_CHARS),
    reply_to: truncate_(message.getReplyTo() || '', LIMITS.HEADER_CHARS),
    subject: truncate_(message.getSubject() || '', 300),
    body_text: truncate_(message.getPlainBody() || '', LIMITS.BODY_CHARS),
    authentication_results: getAuthenticationResults_(message),
    links: extractLinks_(message.getBody() || ''),
    attachments: describeAttachments_(message),
  };
}

/**
 * getHeader() returns only one value, so read every Authentication-Results
 * line from the raw headers, top to bottom (the backend trusts only the first).
 */
function getAuthenticationResults_(message) {
  var raw = message.getRawContent();
  var headerBlock = raw.split(/\r?\n\r?\n/, 1)[0];
  var unfolded = headerBlock.replace(/\r?\n[ \t]+/g, ' ');
  return unfolded
    .split(/\r?\n/)
    .filter(function (line) { return /^authentication-results:/i.test(line); })
    .map(function (line) {
      return truncate_(line.replace(/^authentication-results:\s*/i, ''), LIMITS.HEADER_CHARS);
    })
    .slice(0, 10);
}

/**
 * Collects <a href> targets and their visible text. We only read the HTML,
 * never render it. Accepts double-quoted, single-quoted and unquoted href
 * values. A regex is not a full HTML parser (Apps Script has none for HTML);
 * see the README limitations.
 */
function extractLinks_(html) {
  var links = [];
  var re = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi;
  var m;
  while ((m = re.exec(html)) !== null && links.length < LIMITS.LINKS) {
    var href = m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]);
    links.push({
      href: truncate_(decodeEntities_(href.trim()), LIMITS.HREF_CHARS),
      text: truncate_(decodeEntities_(m[4].replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim(),
                      LIMITS.LINK_TEXT_CHARS),
    });
  }
  return links;
}

/** Metadata and a SHA-256 hash only. File contents never leave Gmail. */
function describeAttachments_(message) {
  return message.getAttachments({ includeInlineImages: false })
    .slice(0, LIMITS.ATTACHMENTS)
    .map(function (att) {
      var size = att.getSize();
      return {
        filename: truncate_(att.getName() || 'unnamed', 255),
        content_type: truncate_(att.getContentType() || '', 255),
        size: size,
        sha256: size <= LIMITS.HASH_MAX_BYTES ? sha256Hex_(att.getBytes()) : '',
      };
    });
}

// --------------------------------------------------------------- backend

function callBackend_(payload) {
  var baseUrl = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');
  if (!baseUrl) throw new Error('BACKEND_URL script property is not set');

  var response = UrlFetchApp.fetch(baseUrl.replace(/\/$/, '') + '/analyze', {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    headers: { Authorization: 'Bearer ' + ScriptApp.getIdentityToken() },
    muteHttpExceptions: true,
  });

  var code = response.getResponseCode();
  if (code !== 200) throw new Error('Backend returned HTTP ' + code + ': ' + response.getContentText().slice(0, 200));
  return JSON.parse(response.getContentText());
}

// -------------------------------------------------------------------- UI

function buildResultCard_(result) {
  var verdict = VERDICTS[result.verdict] || VERDICTS.suspicious;
  var all = result.findings || [];
  var findings = all.filter(function (f) { return f.points > 0; });
  var notes = all.filter(function (f) { return f.points === 0; });
  var incomplete = notes.filter(function (f) { return /unavailable/i.test(f.title); });

  // "Low risk" must never silently mean "not checked".
  var advice = verdict.advice;
  if (result.verdict === 'safe' && incomplete.length > 0) {
    advice = 'No warning signs in the checks that ran, but ' + incomplete.length +
      (incomplete.length === 1 ? ' check' : ' checks') + ' could not run. See Notes.';
  }

  var summary = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText('<font color="' + verdict.color + '"><b>' + verdict.label + '</b></font>')
      .setBottomLabel('Risk score: ' + Number(result.score) + ' / 100'))
    .addWidget(CardService.newTextParagraph().setText(advice));

  var reasons = CardService.newCardSection().setHeader('Why');
  if (findings.length === 0) {
    reasons.addWidget(CardService.newTextParagraph()
      .setText('Checked sender authentication, sender identity, reply address, links, attachments and wording.'));
  }
  findings.forEach(function (f) {
    reasons.addWidget(CardService.newDecoratedText()
      .setText('<b>' + escape_(f.title) + '</b>')
      .setBottomLabel(escape_(f.detail))
      .setWrapText(true));
  });

  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('PhishLens'))
    .addSection(summary)
    .addSection(reasons);

  var xray = buildLinkXraySection_(result.link_xray);
  if (xray) card.addSection(xray);

  // Checks that could not run, or did not apply, are shown rather than hidden,
  // so "Safe" never silently means "not checked".
  if (notes.length > 0) {
    var notesSection = CardService.newCardSection().setHeader('Notes');
    notes.forEach(function (f) {
      notesSection.addWidget(CardService.newTextParagraph()
        .setText('<font color="#5F6368">' + escape_(f.title) + ': ' + escape_(f.detail) + '</font>'));
    });
    card.addSection(notesSection);
  }

  return card.build();
}

/** Link X-Ray: what each link says next to where it really goes. */
function buildLinkXraySection_(xray) {
  if (!xray || !xray.rows || xray.rows.length === 0) return null;

  var section = CardService.newCardSection()
    .setHeader('Link X-Ray: where links really go')
    .setCollapsible(xray.rows.length > 3)
    .setNumUncollapsibleWidgets(3);

  xray.rows.forEach(function (row) {
    var mark = row.flagged ? '<font color="#D93025">\u26A0 </font>' : '<font color="#188038">\u2713 </font>';
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel('Shows: ' + escape_(row.shown))
      .setText(mark + 'Opens <b>' + escape_(row.opens) + '</b>')
      .setWrapText(true));
  });

  var hidden = Number(xray.total) - xray.rows.length;
  if (hidden > 0) {
    section.addWidget(CardService.newTextParagraph()
      .setText('<font color="#5F6368">+ ' + hidden + ' more links</font>'));
  }
  return section;
}

/** Shown when the analysis could not run. Never claims the message is safe. */
function buildErrorCard_() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('PhishLens'))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph()
      .setText('Could not analyze this message right now. Treat it with your usual caution.')))
    .build();
}

// --------------------------------------------------------------- helpers

/** Card text allows a little HTML, so anything derived from the email is escaped. */
function escape_(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Turns HTML character references back into characters, so that
 * "paypal&#46;com" and "paypal&#x2e;com" are seen as "paypal.com".
 * &amp; is decoded last, so "&amp;#46;" stays the literal text "&#46;".
 */
function decodeEntities_(s) {
  function fromCode(code, original) {
    return code > 0 && code <= 0x10FFFF ? String.fromCodePoint(code) : original;
  }
  return s
    .replace(/&#x([0-9a-f]+);?/gi, function (m, hex) { return fromCode(parseInt(hex, 16), m); })
    .replace(/&#(\d+);?/g, function (m, dec) { return fromCode(parseInt(dec, 10), m); })
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&');
}

function truncate_(s, max) {
  s = String(s == null ? '' : s);
  return s.length > max ? s.slice(0, max) : s;
}

function sha256Hex_(bytes) {
  return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes)
    .map(function (b) { return ('0' + (b & 0xff).toString(16)).slice(-2); })
    .join('');
}