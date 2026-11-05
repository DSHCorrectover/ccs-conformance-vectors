#!/usr/bin/env python3
"""IICP x CCS pilot — offline receipt verifier (CC0).
Usage: python verify_pilot.py fixtures/case-C1-receipt.json
Exit 0 = signature valid; 1 = INVALID (tamper detected)."""
import json,sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
PUB="""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAel5JkEEz+riY9n5/JrM+5KIidMxN9ZVOCwyE2FsHdxI=
-----END PUBLIC KEY-----"""
def jcs(o): return json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
r=json.load(open(sys.argv[1]))
p=r['payload']
sig=bytes.fromhex(r['signature_hex'])
canon=jcs(p)
pk=serialization.load_pem_public_key(PUB.encode())
try:
    pk.verify(sig,canon)
    print("VALID — signature binds payload:",p['case_id'],p['verdict'])
    sys.exit(0)
except Exception:
    print("INVALID — signature verification FAILED (tamper detected)")
    sys.exit(1)
