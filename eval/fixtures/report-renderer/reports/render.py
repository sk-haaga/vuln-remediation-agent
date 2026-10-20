"""Render HTML reports. Uses jinja2.Markup, which Jinja2 3.x removed."""
from jinja2 import Environment, Markup
from mako.template import Template
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import SqlLexer
import sqlparse

_env = Environment(autoescape=True)


def badge(text: str) -> Markup:
    return Markup("<span class='badge'>%s</span>") % text


def render_jinja(title: str, items: list[str]) -> str:
    tpl = _env.from_string("<h1>{{ title }}</h1><ul>{% for i in items %}<li>{{ i }}</li>{% endfor %}</ul>{{ b }}")
    return tpl.render(title=title, items=items, b=badge("ok"))


def render_mako(name: str) -> str:
    return Template("Hello ${name}!").render(name=name)


def pretty_sql(sql: str) -> str:
    formatted = sqlparse.format(sql, reindent=True, keyword_case="upper")
    return highlight(formatted, SqlLexer(), HtmlFormatter())
