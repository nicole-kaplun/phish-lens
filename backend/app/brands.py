"""Brand knowledge shared by several analyzers.

Both the sender check and the link check need to answer "does this look like
a well-known brand?", so that logic lives here once instead of being copied.
"""
import re
import unicodedata

# Brand keyword -> domains that legitimately send mail as that brand.
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com"],
    "apple": ["apple.com"],
    "google": ["google.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dhl": ["dhl.com"],
    "leumi": ["leumi.co.il"],
    "hapoalim": ["bankhapoalim.co.il"],
}
# How each brand is written for people. Keys match BRANDS.
_DISPLAY_NAMES = {"paypal": "PayPal", "docusign": "DocuSign", "dhl": "DHL",
                  "leumi": "Bank Leumi", "hapoalim": "Bank Hapoalim"}


def brand_label(brand: str) -> str:
    return _DISPLAY_NAMES.get(brand, brand.title())
# Characters that look like Latin letters. Attackers use them so that a
# naive search for "paypal" misses "pаypal" (Cyrillic а) or "PayPaI" (capital I).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s",
    "0": "o", "1": "l", "|": "l", "i": "l",
})
_INVISIBLE = re.compile(r"[\u200b-\u200f\u2060\ufeff\u00ad]")
_SPACED_LETTERS = re.compile(r"\b(?:\w[ .\-_]){2,}\w\b")


def normalize(text: str) -> str:
    """Reduce text to a 'skeleton' so look-alike spellings compare equal."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    text = text.lower()
    text = _SPACED_LETTERS.sub(lambda m: re.sub(r"[ .\-_]", "", m.group()), text)
    text = text.replace("rn", "m").replace("vv", "w")  # "rn" looks like "m"
    return text.translate(_CONFUSABLES)


def belongs_to(domain: str, allowed: list[str]) -> bool:
    # "mail.paypal.com" belongs to paypal.com; "paypal.com.evil.com" does not.
    return any(domain == d or domain.endswith("." + d) for d in allowed)


def _decode_punycode(domain: str) -> str:
    # "xn--pypal-4ve.com" is how "pаypal.com" (Cyrillic а) travels on the wire.
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return domain


def _one_edit_apart(a: str, b: str) -> bool:
    """True if a and b differ by exactly one insert, delete or substitution."""
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = j = edits = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            edits += 1
            if edits > 1:
                return False
            if len(a) == len(b):
                i += 1
            j += 1
        else:
            i += 1
            j += 1
    return edits + (len(b) - j) == 1


def lookalike_brand(domain: str) -> str | None:
    """Return the brand a domain imitates, or None.

    Catches: paypa1.com, pаypal.com (punycode), paypal-secure.net,
    paypal.com.evil.com and one-typo variants such as paypall.com.
    """
    domain = _decode_punycode(domain.lower())
    labels = domain.split(".")[:-1]  # drop the TLD
    for brand, legit in BRANDS.items():
        if belongs_to(domain, legit):
            continue
        target = normalize(brand)
        for label in labels:
            skeleton = normalize(label)
            if skeleton == target or target in re.split(r"[-_]", skeleton):
                return brand
            if len(target) >= 5 and _one_edit_apart(skeleton, target):
                return brand
    return None