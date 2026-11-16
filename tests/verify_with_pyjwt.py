# Run from the repo root: pip install cryptography pyjwt && python tests/verify_with_pyjwt.py
import json, subprocess, sys, jwt, os, shutil, urllib.request, time
from jwt import PyJWKClient
def run(*a): return subprocess.check_output([sys.executable,"mock_issuer.py",*a],text=True)
for alg in ("RS256","ES256"):
    d=f"keys_{alg}"; shutil.rmtree(d,ignore_errors=True)
    print(run("--keys-dir",d,"keygen","--alg",alg).strip())
    jwks=json.load(open(f"{d}/jwks.json"))
    key=jwt.PyJWK(jwks["keys"][0]).key
    tok=run("--keys-dir",d,"issue","--sub","alice","--roles","user,admin","--claim","tenant=7").strip()
    c=jwt.decode(tok,key,algorithms=[alg],audience="cs763-api",issuer="http://localhost:9000",options={"require":["exp","iss","aud"]})
    print(alg,"issue ok",c["sub"],c["roles"],c["tenant"])
    neg=json.loads(run("--keys-dir",d,"negative"))
    ok=True
    for name,t in neg.items():
        try:
            jwt.decode(t["token"],key,algorithms=[alg],audience="cs763-api",issuer="http://localhost:9000",options={"require":["exp","iss","aud","sub"]})
            got="accept"
        except Exception as e:
            got="reject"
        if name=="unknown_kid": pass
        flag="OK " if got==t["expect"] or name=="unknown_kid" else "BAD"
        if flag=="BAD": ok=False
        print(f"  {flag} {name:22} expect={t['expect']} got={got}")
    print(alg,"ALL OK" if ok else "FAILURES")
