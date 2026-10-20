import certifi
import idna
from tqdm import tqdm


def ca_bundle() -> str:
    return certifi.where()


def to_ascii_host(host: str) -> str:
    return idna.encode(host).decode("ascii")


def rotate_all(user_ids):
    return [uid.upper() for uid in tqdm(user_ids, disable=True)]
