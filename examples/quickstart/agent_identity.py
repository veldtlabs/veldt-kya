"""Mint a DID + proof-of-possession. No shared secret, no trusted header."""
import base64
import json
import time

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _b64(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")

def new_agent_identity():
    sk = Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64(raw)}
    did = "did:jwk:" + _b64(json.dumps(jwk).encode())
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    return did, pem

def proof(did, pem, audience):
    now = int(time.time())
    return pyjwt.encode({"iss": did, "aud": audience, "iat": now, "exp": now + 60},
                        pem, algorithm="EdDSA", headers={"kid": f"{did}#0"})
