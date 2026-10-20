"""Session tokens. Written against PyJWT 1.x, where encode() returns bytes."""
import datetime

import jwt

SECRET = "change-me"


def issue(user_id: str, minutes: int = 15) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutes),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256").decode("utf-8")


def verify(token: str) -> str:
    return jwt.decode(token, SECRET, algorithms=["HS256"])["sub"]
