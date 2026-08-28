#!/usr/bin/env python3
"""Independent verifier for CCS v1.3.1 paired conformance vectors."""
import base64, copy, glob, hashlib, json, os, sys
import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from ccs_verifier.ccs_verifier_l1 import L1Receipt

BASE = os.path.join(os.path.dirname(__file__), "vectors", "v1.3.0")

def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def verify_signed_json(obj):
    signed = {k: v for k, v in obj.items() if k != "signature"}
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(obj["public_key"]))
    pub.verify(base64.b64decode(obj["signature"]), jcs.canonicalize(signed))

def main():
    manifest = load(os.path.join(BASE, "manifest.json"))
    assert manifest["manifest_version"] == "1.3.1"
    for entry in manifest["files"]:
        path = os.path.join(BASE, entry["path"])
        assert hashlib.sha256(open(path, "rb").read()).hexdigest() == entry["sha256"], entry["path"]
    for path in sorted(glob.glob(os.path.join(BASE, "*", "action-*.json"))):
        receipt = L1Receipt.from_dict(load(path), strict=True)
        assert receipt.verify_signature(), path
    for path in sorted(glob.glob(os.path.join(BASE, "*", "behavior-*.json"))):
        obs = load(path)
        verify_signed_json(obs)
        l1_path = path.replace("behavior-", "action-")
        l1 = load(l1_path)
        expected = "sha256:" + hashlib.sha256(jcs.canonicalize({k:v for k,v in l1.items() if k!="signature"})).hexdigest()
        assert obs["linked_l1_receipt_digest"] == expected, path
    print("v1.3.1 verification passed: L1 signatures, behavior signatures, linkage, and manifest hashes OK")

if __name__ == "__main__":
    main()
