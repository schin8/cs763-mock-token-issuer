# CS763 Mock Token Issuer

A key-generation and mock token issuer tool for Project Assignment 3. It stands in for a real identity provider, so you can spend your time on validating tokens and authorizing requests in your service rather than building login flows.

**For local development and testing only.** Do not deploy it or reuse its keys anywhere else.

## What it does

- Generates an RS256 (RSA 2048) or ES256 (P-256) signing key pair and a JWKS file
- Issues signed JWTs with `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, and `roles`
- Produces a set of labeled bad tokens for your negative tests (expired, wrong issuer, wrong audience, `alg: none`, HS256 key confusion, bad signature, tampered payload, and more)
- Runs a small HTTP server with a JWKS endpoint and a token endpoint, so it can run as a service in Docker Compose

The only dependency is Python 3.9+ and the `cryptography` package.

## Quick start (command line)

```bash
pip install cryptography

python mock_issuer.py keygen                  # RS256 by default; use --alg ES256 for EC
python mock_issuer.py issue --sub alice       # prints a token for user "alice"
python mock_issuer.py issue --sub bob --roles user,admin --ttl 600
python mock_issuer.py negative --out negative-tokens.json
python mock_issuer.py decode <token>          # shows header and payload, no verification
```

Keys are written to `keys/` (`private.pem`, `public.pem`, `jwks.json`). **Never commit `private.pem`.** Add `keys/` to your `.gitignore`.

Call your API with:

```bash
TOKEN=$(python mock_issuer.py issue --sub alice)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/...
```

## Running as a service (Docker Compose)

Copy `mock_issuer.py` and the `Dockerfile` into a folder in your repository, for example `token-issuer/`, then add a service:

```yaml
services:
  token-issuer:
    build: ./token-issuer
    ports:
      - "9000:9000"
    environment:
      ISSUER: http://localhost:9000
      AUDIENCE: cs763-api
      ALG: RS256
    volumes:
      - issuer-keys:/app/keys        # keeps the same keys across restarts

  api:
    build: ./secure-codebase
    depends_on:
      - token-issuer
    environment:
      JWT_JWK_SET_URI: http://token-issuer:9000/.well-known/jwks.json
      JWT_ISSUER: http://localhost:9000
      JWT_AUDIENCE: cs763-api

volumes:
  issuer-keys:
```

The `iss` value is just a string your service compares against. Use the same `ISSUER` in the issuer and in your API configuration. Inside Compose, your API fetches keys from `http://token-issuer:9000`, while you request tokens from your machine at `http://localhost:9000`.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/jwks.json` | Public keys your service uses to verify signatures |
| GET | `/.well-known/openid-configuration` | Discovery document |
| POST | `/token` | Issue a token. Form or JSON body: `sub=alice&roles=user,admin&ttl=3600` |
| GET | `/negative?sub=alice&other_sub=bob` | Labeled good and bad tokens as JSON |
| GET | `/health` | Status, issuer, audience, alg, kid |

```bash
curl -s -X POST -d "sub=alice&roles=user" http://localhost:9000/token
```

## Negative tests

`negative` (or `GET /negative`) returns JSON like:

```json
{
  "valid":            { "expect": "accept", "why": "...", "token": "..." },
  "expired":          { "expect": "reject", "why": "...", "token": "..." },
  ...
}
```

| Token | Your service should | What it tests |
|---|---|---|
| `valid` | accept | Baseline |
| `valid_other_user` | accept the token, but deny access to alice's records (403 or 404) | Row-level authorization |
| `expired` | reject (401) | `exp` validation |
| `not_yet_valid` | reject | `nbf` validation |
| `missing_exp` | reject | Requiring `exp` |
| `wrong_issuer` | reject | `iss` validation |
| `wrong_audience` | reject | `aud` validation |
| `alg_none` | reject | Algorithm allowlist blocks `none` |
| `hs256_key_confusion` | reject | Algorithm allowlist blocks HS256 (attacker signs with your public key as an HMAC secret) |
| `bad_signature` | reject | Signature verification |
| `tampered_payload` | reject | Payload changed after signing |
| `unknown_kid` | reject | Key not in the JWKS |
| `malformed` | reject | Input handling |

Tokens are time-sensitive (`exp` defaults to one hour), so generate them at the start of a test run rather than committing them.

## Configuration

| Setting | CLI flag | Environment variable | Default |
|---|---|---|---|
| Keys directory | `--keys-dir` | `KEYS_DIR` | `keys` |
| Algorithm | `--alg` | `ALG` | `RS256` |
| Issuer | `--iss` | `ISSUER` | `http://localhost:9000` |
| Audience | `--aud` | `AUDIENCE` | `cs763-api` |
| Token lifetime (seconds) | `--ttl` | `TOKEN_TTL` | `3600` |
| Port (serve) | `--port` | `PORT` | `9000` |

Extra claims: `issue --sub alice --claim tenant=7 --claim email=alice@example.com`.

## Spring Boot

See `examples/spring-boot/SecurityConfigExample.java` for a resource server configuration with an RS256/ES256 allowlist and `iss`, `aud`, and `exp` validation, plus a row-level authorization example. Other stacks can use any JWT library that supports a JWKS URL and an algorithm allowlist (for example, `jose` in Node or `PyJWT` in Python).

## Notes

- `roles` is a JSON array, and `scope` repeats the roles as a space-separated string, so either style of authority mapping works.
- `kid` is the RFC 7638 thumbprint of the public key, so it changes when you regenerate keys.
- If you regenerate keys, restart your API or let it refetch the JWKS.
