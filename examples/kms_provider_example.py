"""Reference KMS-backed signing-key provider for KYA evidence.

Plug-in shape — `KYA_EVIDENCE_KEY_PROVIDER=module:function` resolves to
a callable returning `(key_bytes, key_id_str)`. The function below shows
the contract; replace the stub body with real KMS / Vault / sealed-secret
fetches for production.

Wire-up
-------
    export KYA_EVIDENCE_KEY_PROVIDER="kms_provider_example:get_key"
    python your_agent.py

KYA loads the function on first signing operation.

Patterns for the three common KMS providers
-------------------------------------------

AWS KMS (envelope-key pattern):
    import boto3
    _KMS = boto3.client("kms")
    _CACHED = None

    def get_key():
        global _CACHED
        if _CACHED is None:
            resp = _KMS.generate_data_key(
                KeyId=os.environ["KYA_AWS_KMS_KEY_ARN"],
                KeySpec="AES_256",
            )
            _CACHED = (resp["Plaintext"], resp["KeyId"].split("/")[-1])
        return _CACHED

GCP Cloud KMS:
    from google.cloud import kms
    _CLIENT = kms.KeyManagementServiceClient()
    _KEY_NAME = os.environ["KYA_GCP_KMS_KEY_NAME"]
    _CACHED = None

    def get_key():
        global _CACHED
        if _CACHED is None:
            # Cloud KMS doesn't return raw material — derive a key via
            # `mac_sign` operations OR use Cloud KMS's data-key envelope.
            ...
        return _CACHED

HashiCorp Vault (Transit secrets engine):
    import hvac
    _VAULT = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])

    def get_key():
        resp = _VAULT.secrets.transit.read_key(name="kya-evidence-v1")
        # exportable key — or use Vault's `sign` operation if non-exportable
        ...
"""

import base64
import os

# Example stub — real implementation should fetch from KMS / Vault.
# DO NOT use this in production; it just demonstrates the contract.


def get_key() -> tuple[bytes, str]:
    """Return (key_bytes, key_id_str).

    key_bytes  — at least 16 bytes (32 recommended for SHA-256 HMAC).
    key_id_str — opaque identifier persisted on every signed row so
                 future rotation knows which key signed what.
    """
    raw = os.environ.get("KYA_EXAMPLE_KMS_KEY_B64")
    if not raw:
        raise RuntimeError(
            "kms_provider_example.get_key: set KYA_EXAMPLE_KMS_KEY_B64 "
            "to demonstrate. In production, replace this body with a "
            "real KMS / Vault fetch."
        )
    key = base64.b64decode(raw)
    return key, "example-v1"
