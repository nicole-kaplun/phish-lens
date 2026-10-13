/**
 * PhishLens - Gmail add-on.
 *
 * The add-on only collects what the backend needs and shows the result.
 * All detection logic and any API keys live in the backend, so nothing
 * sensitive is stored here (this file is public on GitHub).
 */

var LIMITS = {
  HEADER_CHARS: 4000,
  LINKS: 100,
  HREF_CHARS: 2048,
  LINK_TEXT_CHARS: 500,
  ATTACHMENTS: 20,
  HASH_MAX_BYTES: 10 * 1024 * 1024,
};

var VERDICTS = {
  safe:       { label: 'Safe',       color: '#188038', advice: 'No warning signs found.' },
  suspicious: { label: 'Suspicious', color: '#E37400', advice: 'Check before you click links or open attachments.' },
  malicious:  { label: 'Malicious',  color: '#D93025', advice: 'Do not click links or open attachments. Report and delete.' },
};

/** Contextual trigger: Gmail calls this every time the user opens a message. */
function onGmailMessageOpen(e) {
  try {
    GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
    var message = GmailApp.getMessageById(e.gmail.messageId);
    var result = callBackend_(extractPayload_(message));
    return buildResultCard_(result);
  } catch (err) {
    console.error(err);
    return buildErrorCard_();
  }
}

// ------------------------------------------------------------ extraction

/** Only the fields the backend's checks use. Subject and body are not sent. */
function extractPayload_(message) {
  return {
    from_header: truncate_(message.getFrom(), LIMITS.HEADER_CHARS),
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

/** Collects <a href> targets and their visible text. We only read the HTML, never render it. */
function extractLinks_(html) {
  var links = [];
  var re = /<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  var m;
  while ((m = re.exec(html)) !== null && links.length < LIMITS.LINKS) {
    links.push({
      href: truncate_(decodeEntities_(m[1].trim()), LIMITS.HREF_CHARS),
      text: truncate_(decodeEntities_(m[2].replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim(),
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

  var summary = CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setTopLabel('Verdict')
      .setText('<font color="' + verdict.color + '"><b>' + verdict.label + '</b></font>')
      .setBottomLabel('Risk score: ' + Number(result.score) + ' / 100'))
    .addWidget(CardService.newTextParagraph().setText(verdict.advice));

  var reasons = CardService.newCardSection().setHeader('Why');
  if (findings.length === 0) {
    reasons.addWidget(CardService.newTextParagraph()
      .setText('Checked sender authentication, sender identity, links and attachments.'));
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
// --------------------------------------------------------------- helpers

/** Card text allows a little HTML, so anything derived from the email is escaped. */
function escape_(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** href="...&amp;..." in HTML means "&" in the real URL. */
function decodeEntities_(s) {
  return s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
          .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ');
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