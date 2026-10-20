import os

from authsvc import signing, tokens, util


def test_token_round_trip():
    assert tokens.verify(tokens.issue("alice")) == "alice"


def test_signature():
    key = signing.new_key()
    sig = signing.sign(key, b"payload")
    assert signing.verify(key, b"payload", sig)


def test_utils():
    assert os.path.exists(util.ca_bundle())
    assert util.to_ascii_host("bücher.example") == "xn--bcher-kva.example"
    assert util.rotate_all(["a", "b"]) == ["A", "B"]
