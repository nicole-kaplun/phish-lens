"""Link X-Ray: what each link shows versus where it really goes."""
from tests.conftest import email


def test_xray_shows_real_destination_and_flags_first(client):
    result = client.post("/analyze", json=email(links=[
        {"href": "https://www.paypal.com/help", "text": "Help Center"},
        {"href": "https://evil.com/x", "text": "paypal.com/login"},
        {"href": "mailto:help@paypal.com", "text": "Email us"},
    ])).json()
    rows = result["link_xray"]["rows"]
    assert rows[0] == {"shown": "paypal.com/login", "opens": "evil.com", "flagged": True}
    assert rows[1] == {"shown": "Help Center", "opens": "www.paypal.com", "flagged": False}
    assert result["link_xray"]["total"] == 2  # mailto is not a web link


def test_xray_merges_duplicates_and_caps_rows(client):
    many = [{"href": f"https://site{i}.com", "text": "Read more"} for i in range(15)]
    xray = client.post("/analyze", json=email(links=many + many)).json()["link_xray"]
    assert xray["total"] == 15 and len(xray["rows"]) == 10


def test_xray_uses_host_a_browser_would_visit(client):
    rows = client.post("/analyze", json=email(links=[
        {"href": "https://paypal.com@evil.com/login", "text": "Click"}])).json()["link_xray"]["rows"]
    assert rows[0]["opens"] == "evil.com" and rows[0]["flagged"]


def test_html_entities_are_decoded_like_a_browser(client):
    # Named entities the add-on used to miss: "&period;" is ".", "&sol;" is "/".
    result = client.post("/analyze", json=email(links=[
        {"href": "https&colon;&sol;&sol;paypa1&period;com/login", "text": "paypal&period;com"}])).json()
    assert result["link_xray"]["rows"][0] == {"shown": "paypal.com", "opens": "paypa1.com", "flagged": True}
    assert "Link to a domain imitating PayPal" in [f["title"] for f in result["findings"]]