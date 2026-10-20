# Security: pyjwt 1.7.1 needs manual review (tests-failed)

The smallest safe upgrade breaks the test suite, so the agent did not open a pull request. The smallest safe version is 2.15.0 (major upgrade from 1.7.1). A major upgrade often needs code changes; the test output below shows where.

### Facts (generated from tool results)

- Package: `pyjwt` (found by requirements)
- Current version: `1.7.1`
- Proposed version: `2.15.0` (major upgrade)
- Tests with the upgrade: **failed at the tests step (exit 1)** in 4s

| Advisory | Summary | Fixed in |
|---|---|---|
| CVE-2022-29217 | PyJWT supports multiple different JWT signing algorithms. | 2.4.0 |
| CVE-2025-45768 | pyjwt v2.10.1 was discovered to contain weak encryption. | no fix released |
| CVE-2026-101917 | CVE-2026-48524 (GHSA-fhv5-28vv-h8m8, "PyJWKClient unbounded JWKS endpoint requests via attacker-controlled kid values (DoS)") was fixed in 2.13.0 by stopping fetch_data() from clearing the cache on a fetch error. | 2.14.0 |
| CVE-2026-102267 | PyJWT 2.13.0 PyJWKClient followed HTTP redirects while fetching a JWKS, without validating the redirect destination. | 2.14.0 |
| CVE-2026-102268 | Prerequisites (both conditions must hold; both are deployment properties, not attacker-controlled at request time): - The jwt.decode allow-list mixes an HMAC algorithm with an asymmetric one, e.g. | 2.14.0 |
| CVE-2026-102269 | PyJWT 2.13.0 accepts compact JWS signature segments containing characters that are not in the Base64URL alphabet. | 2.14.0 |
| CVE-2026-102270 | There is a Re-DoS vulnerability in the is_pem_format function which results in a intesive CPU usage if an attacker is been able to provide a custom certificate. | 2.14.0 |
| CVE-2026-32597 | Prior to 2.12.0, PyJWT does not validate the crit (Critical) Header Parameter defined in RFC 7515 §4.1.11. | 2.12.0 |
| CVE-2026-48522 | Prior to 2.13.0, PyJWKClient passes its uri argument directly to urllib.request.urlopen() which uses Python stdlib's default OpenerDirector registering HTTPHandler, HTTPSHandler, FTPHandler, FileHandler, and DataHandler. | 2.13.0 |
| CVE-2026-48524 | Prior to 2.13.0, PyJWKClient.get_signing_key() forces a fresh HTTP request to the JWKS endpoint for every JWT with an unknown kid value, with no rate limiting. | 2.13.0 |
| CVE-2026-48526 | Prior to 2.13.0, when the verifier is decoding JSON Web Tokens, while supporting both asymmetric and HMAC algorithms, the library does not validate use of JSON Web Keys in HMAC algorithm, allowing attacker to use the is… | 2.13.0 |

<details><summary>Test output (last lines)</summary>

```
F..                                                                      [100%]
=================================== FAILURES ===================================
____________________________ test_token_round_trip _____________________________

    def test_token_round_trip():
>       assert tokens.verify(tokens.issue("alice")) == "alice"

tests/test_auth.py:7: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 

user_id = 'alice', minutes = 15

    def issue(user_id: str, minutes: int = 15) -> str:
        payload = {
            "sub": user_id,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=minutes),
        }
>       return jwt.encode(payload, SECRET, algorithm="HS256").decode("utf-8")
E       AttributeError: 'str' object has no attribute 'decode'. Did you mean: 'encode'?

authsvc/tokens.py:14: AttributeError
=============================== warnings summary ===============================
tests/test_auth.py::test_token_round_trip
  /tmp/vra-uv0hfh2t/pyjwt/.vra-venv/lib/python3.13/site-packages/jwt/api_jwt.py:149: InsecureKeyLengthWarning: The HMAC key is 9 bytes long, which is below the minimum recommended length of 32 bytes for SHA256. See RFC 7518 Section 3.2.
    return self._jws.encode(

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
=========================== short test summary info ============================
FAILED tests/test_auth.py::test_token_round_trip - AttributeError: 'str' obje...
1 failed, 2 passed, 1 warning in 0.07s

```
</details>

---
_Opened by vuln-remediation-agent. The agent never merges: a person reviews and decides._
