"""Look-alike detection: real domains pass, imitations are caught."""
import pytest

from app.brands import lookalike_brand, normalize


@pytest.mark.parametrize("domain,brand", [
    ("paypal.com", None),
    ("mail.paypal.com", None),
    ("paypa1.com", "paypal"),
    ("xn--pypal-4ve.com", "paypal"),
    ("paypal-secure.net", "paypal"),
    ("paypal.com.evil.com", "paypal"),
    ("paypall.com", "paypal"),
    ("rnicrosoft.com", "microsoft"),
    ("pineapplefarm.com", None),
    ("gmail.com", None),
])
def test_lookalike_brand(domain, brand):
    assert lookalike_brand(domain) == brand


@pytest.mark.parametrize("text,skeleton", [
    ("PayPaI", "paypal"),
    ("P a y P a l", "paypal"),
    ("Pаypal", "paypal"),          # Cyrillic а
    ("Pay\u200bPal", "paypal"),    # zero-width space
])
def test_normalize_defeats_lookalike_spellings(text, skeleton):
    assert normalize(text) == skeleton
