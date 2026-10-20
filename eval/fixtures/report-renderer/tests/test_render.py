from reports import render


def test_jinja_escapes_and_badges():
    html = render.render_jinja("<Q3>", ["a&b"])
    assert "&lt;Q3&gt;" in html and "a&amp;b" in html
    assert "<span class='badge'>ok</span>" in html


def test_mako():
    assert render.render_mako("Ada") == "Hello Ada!"


def test_sql():
    out = render.pretty_sql("select id from users where id=1")
    assert "SELECT" in out and "highlight" in out
