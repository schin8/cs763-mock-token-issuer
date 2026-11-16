# Tool: Claude (Anthropic), via Claude Code
# Prompt Summary: "Write pytest tests for the mock token issuer: signatures, claims,
#   negative set, HTTP input handling, and CLI behavior."
# AI Contribution: Initial draft (~90%)
# Human Modifications:
# - Added the key-creation message test and reviewed the test names
# Verification:
# - Run with python -m pytest tests/ (23 tests passing at v1.0.0)
# Confidence: Medium
"""Unit and HTTP tests for mock_issuer.py.

Run from the repo root:
    pip install cryptography pyjwt pytest
    python -m pytest tests/
"""
import http.client
import json
import os
import sys
import tempfile
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import mock_issuer  # noqa: E402
from mock_issuer import Handler, b64url_decode, load_keys, parse_extra  # noqa: E402


EXPECTED_NEGATIVE_NAMES = {
    "valid", "valid_other_user", "expired", "not_yet_valid", "missing_exp",
    "wrong_issuer", "wrong_audience", "valid_aud_array", "expired_2min", "alg_none",
    "hs256_key_confusion", "bad_signature", "tampered_payload", "unknown_kid",
    "alg_not_allowed", "jku_injection", "malformed",
}


@pytest.fixture(scope="module")
def keys_dir():
    with tempfile.TemporaryDirectory() as tmp:
        mock_issuer.keygen(tmp, "RS256")
        yield tmp


@pytest.fixture
def server(keys_dir):
    """Run the real HTTP handler on a free port. Resets the secret after each test."""
    key, alg, jwk = load_keys(keys_dir)
    Handler.key, Handler.alg, Handler.jwk = key, alg, jwk
    Handler.issuer, Handler.audience = "http://localhost:9000", "cs763-api"
    Handler.issue_secret = None
    srv = mock_issuer.IssuerServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()
        Handler.issue_secret = None


def request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


# ---------------------------------------------------------------- signing

def test_es256_signature_is_raw_64_bytes(keys_dir):
    with tempfile.TemporaryDirectory() as tmp:
        mock_issuer.keygen(tmp, "ES256")
        key, alg, jwk = load_keys(tmp)
        token = mock_issuer.issue_token(key, alg, jwk, sub="alice")
        sig = b64url_decode(token.split(".")[2])
        assert alg == "ES256"
        assert len(sig) == 64  # JWS uses raw R||S, not DER


def test_issued_token_has_expected_claims(keys_dir):
    key, alg, jwk = load_keys(keys_dir)
    token = mock_issuer.issue_token(key, alg, jwk, sub="alice", roles=["user", "admin"])
    payload = json.loads(b64url_decode(token.split(".")[1]))
    assert payload["sub"] == "alice"
    assert payload["roles"] == ["user", "admin"]
    assert payload["scope"] == "user admin"
    assert payload["exp"] - payload["iat"] == mock_issuer.DEFAULT_TTL


# ---------------------------------------------------------------- negative set

def test_negative_set_has_every_expected_case(keys_dir):
    key, alg, jwk = load_keys(keys_dir)
    negatives = mock_issuer.negative_tokens(key, alg, jwk)
    assert set(negatives) == EXPECTED_NEGATIVE_NAMES
    for name, case in negatives.items():
        assert case["expect"] in ("accept", "reject"), name
        assert case["why"], name


# ---------------------------------------------------------------- CLI helpers

def test_reserved_claim_is_rejected():
    with pytest.raises(SystemExit) as err:
        parse_extra(["exp=0"])
    assert "reserved" in str(err.value)


def test_extra_claim_values_are_parsed():
    assert parse_extra(["tenant=7", "email=alice@example.com"]) == {
        "tenant": 7, "email": "alice@example.com"}


# ---------------------------------------------------------------- HTTP

def test_health_reports_alg_and_kid(server):
    status, body = request(server, "GET", "/health")
    data = json.loads(body)
    assert status == 200
    assert data["alg"] == "RS256"
    assert data["audience"] == "cs763-api"


def test_post_token_issues_a_token(server):
    status, body = request(server, "POST", "/token", body="sub=alice&roles=user",
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 200
    assert json.loads(body)["access_token"].count(".") == 2


def test_get_token_is_not_allowed(server):
    status, body = request(server, "GET", "/token?sub=alice")
    assert status == 405
    assert json.loads(body)["error"] == "method_not_allowed"


def test_malformed_json_returns_400(server):
    status, body = request(server, "POST", "/token", body="{bad",
                           headers={"Content-Type": "application/json"})
    assert status == 400
    assert json.loads(body)["error"] == "invalid_request"


def test_json_array_body_returns_400(server):
    status, _ = request(server, "POST", "/token", body="[1]",
                        headers={"Content-Type": "application/json"})
    assert status == 400


def test_non_numeric_content_length_returns_400(server):
    status, _ = request(server, "POST", "/token", body="sub=alice",
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 "Content-Length": "abc"})
    assert status == 400


def test_issue_secret_blocks_requests_without_it(server):
    Handler.issue_secret = "s3cret"
    status, _ = request(server, "POST", "/token", body="sub=alice",
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 401


def test_issue_secret_allows_requests_with_it(server):
    Handler.issue_secret = "s3cret"
    status, _ = request(server, "POST", "/token", body="sub=alice",
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 "X-Issuer-Secret": "s3cret"})
    assert status == 200


def test_issue_secret_does_not_block_jwks(server):
    Handler.issue_secret = "s3cret"
    status, _ = request(server, "GET", "/.well-known/jwks.json")
    assert status == 200


def test_non_numeric_ttl_returns_400(server):
    status, body = request(server, "POST", "/token", body="sub=alice&ttl=abc",
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 400
    assert "ttl" in json.loads(body)["error_description"]


def test_zero_or_negative_ttl_returns_400(server):
    for ttl in ("0", "-5"):
        status, _ = request(server, "POST", "/token", body=f"sub=alice&ttl={ttl}",
                            headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 400, ttl


def test_negative_content_length_returns_400(server):
    status, _ = request(server, "POST", "/token", body="sub=alice",
                        headers={"Content-Type": "application/x-www-form-urlencoded",
                                 "Content-Length": "-1"})
    assert status == 400


def test_oversized_body_returns_413(server):
    big = "sub=alice&pad=" + "x" * (mock_issuer.MAX_BODY_BYTES + 1)
    status, _ = request(server, "POST", "/token", body=big,
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 413


def test_null_or_object_claim_value_returns_400(server):
    for body in ('{"sub": null}', '{"sub": {"a": 1}}'):
        status, _ = request(server, "POST", "/token", body=body,
                            headers={"Content-Type": "application/json"})
        assert status == 400, body


def test_unknown_kid_token_is_signed_by_the_real_key(keys_dir):
    """The unknown_kid case must only fail a kid lookup, not the signature check."""
    key, alg, jwk = load_keys(keys_dir)
    case = mock_issuer.negative_tokens(key, alg, jwk)["unknown_kid"]
    header, payload, sig = case["token"].split(".")
    assert json.loads(b64url_decode(header))["kid"] == "unknown-key-id"
    signing_input = f"{header}.{payload}".encode("ascii")
    key.public_key().verify(b64url_decode(sig), signing_input,
                            mock_issuer.padding.PKCS1v15(), mock_issuer.hashes.SHA256())


def test_alg_none_token_carries_a_kid(keys_dir):
    key, alg, jwk = load_keys(keys_dir)
    token = mock_issuer.negative_tokens(key, alg, jwk)["alg_none"]["token"]
    header = json.loads(b64url_decode(token.split(".")[0]))
    assert header["alg"] == "none"
    assert header["kid"] == jwk["kid"]


def test_decode_rejects_bad_base64_with_a_message():
    import subprocess

    proc = subprocess.run(
        [sys.executable, os.path.join(ROOT, "mock_issuer.py"), "decode", "a.b.c"],
        capture_output=True, text=True)
    assert proc.returncode != 0
    assert "Traceback" not in proc.stderr
    assert "Not a JWT" in proc.stderr


def test_serve_defaults_to_localhost(keys_dir, monkeypatch):
    """Start the real CLI with no HOST set and check the banner shows 127.0.0.1."""
    import subprocess

    monkeypatch.delenv("HOST", raising=False)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "mock_issuer.py"), "--keys-dir", keys_dir,
         "serve", "--port", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        banner = proc.stdout.readline()
    finally:
        proc.kill()
        proc.wait(timeout=5)
    assert "http://127.0.0.1:" in banner


def test_serve_says_when_it_creates_keys(tmp_path):
    """serve makes a key on first start and says so before the banner."""
    import subprocess

    proc = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "mock_issuer.py"), "--keys-dir", str(tmp_path),
         "serve", "--port", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        lines = [proc.stdout.readline(), proc.stdout.readline()]
    finally:
        proc.kill()
        proc.wait(timeout=5)
    assert "Generated a new RS256 key pair" in lines[0]
    assert "http://127.0.0.1:" in lines[1]
    assert os.path.exists(os.path.join(tmp_path, "private.pem"))
