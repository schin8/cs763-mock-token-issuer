#!/usr/bin/env python3
"""Check every labeled token from mock_issuer.py against PyJWT.

Run from anywhere:
    pip install cryptography pyjwt
    python tests/verify_with_pyjwt.py

For each algorithm (RS256 and ES256) it makes a temporary key set, checks a
normal token, then checks each negative token. The verifier looks up the key
by the token's kid, the way a real service should. Keys are written to a temp
folder that is deleted afterwards. The script exits non-zero if any token gets
the wrong result.
"""
import json
import os
import subprocess
import sys
import tempfile

import jwt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ISSUER = "http://localhost:9000"
AUDIENCE = "cs763-api"
REQUIRED = ["exp", "iss", "aud", "sub"]


def run_issuer(keys_dir, *args):
    cmd = [sys.executable, os.path.join(ROOT, "mock_issuer.py"), "--keys-dir", keys_dir, *args]
    return subprocess.check_output(cmd, text=True)


def find_key(jwks, kid):
    """Return the public key with this kid, or None (the same as a service that rejects unknown kids)."""
    for jwk in jwks["keys"]:
        if jwk["kid"] == kid:
            return jwt.PyJWK(jwk).key
    return None


def verify(token, jwks, alg):
    """Return 'accept' or 'reject' the way a service with this config would."""
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.InvalidTokenError:
        return "reject"
    key = find_key(jwks, kid)
    if key is None:
        return "reject"
    try:
        jwt.decode(token, key, algorithms=[alg], audience=AUDIENCE, issuer=ISSUER,
                   options={"require": REQUIRED})
        return "accept"
    except jwt.InvalidTokenError:
        return "reject"


def check_alg(alg, tmp):
    keys_dir = os.path.join(tmp, alg)
    print(run_issuer(keys_dir, "keygen", "--alg", alg).strip())
    with open(os.path.join(keys_dir, "jwks.json")) as f:
        jwks = json.load(f)

    token = run_issuer(keys_dir, "issue", "--sub", "alice", "--roles", "user,admin",
                       "--claim", "tenant=7").strip()
    claims = jwt.decode(token, jwt.PyJWK(jwks["keys"][0]).key, algorithms=[alg],
                        audience=AUDIENCE, issuer=ISSUER, options={"require": REQUIRED})
    print(f"{alg} issue ok: sub={claims['sub']} roles={claims['roles']} tenant={claims['tenant']}")

    negatives = json.loads(run_issuer(keys_dir, "negative"))
    failures = 0
    for name, case in negatives.items():
        got = verify(case["token"], jwks, alg)
        ok = got == case["expect"]
        failures += not ok
        flag = "OK " if ok else "BAD"
        print(f"  {flag} {name:22} expect={case['expect']:<6} got={got}")

    print(f"{alg} {'ALL OK' if failures == 0 else f'{failures} FAILURE(S)'}")
    return failures


def main():
    total = 0
    with tempfile.TemporaryDirectory() as tmp:
        for alg in ("RS256", "ES256"):
            total += check_alg(alg, tmp)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
