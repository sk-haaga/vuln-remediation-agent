import requests
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/hello/<name>")
def hello(name):
    return render_template_string("<p>Hello {{ name }}</p>", name=name)


def build_request(url: str) -> requests.PreparedRequest:
    return requests.Request("GET", url, params={"q": "x y"}).prepare()
