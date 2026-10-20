from webapp.app import app, build_request


def test_health():
    assert app.test_client().get("/health").get_json() == {"status": "ok"}


def test_template_escapes():
    body = app.test_client().get("/hello/<b>").get_data(as_text=True)
    assert "&lt;b&gt;" in body


def test_request_building():
    assert build_request("https://example.com/search").url == "https://example.com/search?q=x+y"
