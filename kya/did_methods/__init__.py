"""Internal DID method resolvers.

Each module here implements ``resolve(suffix: str) -> DIDDocument`` for one
DID method. Resolvers are registered via :func:`kya.did.register_did_method`.

These are deliberately private — the public surface is :mod:`kya.did`.
"""
