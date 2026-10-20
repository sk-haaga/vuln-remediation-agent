"""Detached ECDSA signatures for webhook payloads."""
from ecdsa import NIST256p, SigningKey


def new_key() -> SigningKey:
    return SigningKey.generate(curve=NIST256p)


def sign(key: SigningKey, payload: bytes) -> bytes:
    return key.sign(payload)


def verify(key: SigningKey, payload: bytes, signature: bytes) -> bool:
    return key.get_verifying_key().verify(signature, payload)
