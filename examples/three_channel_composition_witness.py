"""Three-channel composition witness for the only-tighten algebra.

Demonstrates that Lemma 1 (W_t >= W_0) holds across all three channels:
  Channel 1: platform default      W_0
  Channel 2: tenant override       W_t
  Channel 3: signed external rec   W_r   (may target either)

For each attempted update, we report:
  - which channel was written
  - whether only-tighten was enforced (or skipped, for platform-level writes)
  - the effective weight visible to a tenant after the update
  - whether the lemma W_t(tenant) >= W_0 holds

The single-channel (Cedar-style) failure mode is shown as a counterfactual:
if signed recommendations could write at the tenant level WITHOUT the
only-tighten check, an adversary holding the signing key could loosen
a tenant's effective weight via channel 3. KYA's three-channel
composition routes channel 3's tenant-targeted writes through the same
_check_only_tighten guard that channel 2 uses, so the lemma survives.

Run: python examples/three_channel_composition_witness.py
"""

from __future__ import annotations

import sys

TENANT_BANK = "11111111-1111-1111-1111-111111111111"
PLATFORM_DEFAULT_PII = 15


def _setup():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from kya import tenant_weights
    eng = create_engine("sqlite:///:memory:").execution_options(
        schema_translate_map={"prov_schema": None}
    )
    tenant_weights.register_scope("class_weights", {"pii": PLATFORM_DEFAULT_PII})
    Session = sessionmaker(bind=eng)
    db = Session()
    tenant_weights.ensure_tables(db)
    return db


def _effective(db, tenant_id: str | None) -> int:
    """Resolve effective pii weight from the override table directly.

    Uses SQLAlchemy Core so schema_translate_map applies on SQLite.
    Reads the MOST-RECENTLY-INSERTED row (ORDER BY id DESC LIMIT 1)
    because SQLite + default PG behavior treat NULL as distinct in
    UNIQUE indexes, so platform-level writes (tenant_id=NULL) create
    new rows rather than upsert. Production deployments use a partial
    unique index to coalesce; this read mirrors that intent.
    """
    from sqlalchemy import select, and_
    from kya._legacy_tables import kya_weight_overrides as T
    val = PLATFORM_DEFAULT_PII
    plat = db.execute(
        select(T.c.value).where(
            and_(T.c.tenant_id.is_(None), T.c.scope == "class_weights", T.c.key == "pii")
        ).order_by(T.c.id.desc()).limit(1)
    ).scalar()
    if plat is not None:
        val = int(plat)
    if tenant_id is not None:
        tenrow = db.execute(
            select(T.c.value).where(
                and_(T.c.tenant_id == tenant_id, T.c.scope == "class_weights", T.c.key == "pii")
            ).order_by(T.c.id.desc()).limit(1)
        ).scalar()
        if tenrow is not None:
            val = int(tenrow)
    return val


def _try_write(db, *, channel: str, scope: str, key: str,
               value: int, tenant_id: str | None, expected_blocked: bool) -> dict:
    """Try one channel-write; return outcome record."""
    from kya import tenant_weights
    try:
        tenant_weights.set_override(
            db, scope=scope, key=key, value=value, tenant_id=tenant_id,
            changed_by=f"channel-{channel}",
            reason=f"{channel} write of {key}={value} (tenant={tenant_id})",
        )
        blocked = False
        error = None
    except tenant_weights.OverrideLoosensError as exc:
        blocked = True
        error = str(exc)
    return {
        "channel": channel,
        "target": "platform" if tenant_id is None else "tenant",
        "value": value,
        "expected_blocked": expected_blocked,
        "actual_blocked": blocked,
        "match": blocked == expected_blocked,
        "error": error,
    }


def main():
    print("Three-Channel Composition Witness — Lemma 1 (W_t >= W_0)")
    print("=" * 70)
    db = _setup()
    initial = _effective(db, tenant_id=None)
    print(f"Initial platform default W_0(pii) = {initial}")
    print()

    cases = []

    # Channel 1: platform default raise (Veldt operator).
    # Allowed at platform level (no only-tighten check by design).
    cases.append(_try_write(db,
        channel="1-platform-raise", scope="class_weights", key="pii",
        value=18, tenant_id=None, expected_blocked=False,
    ))

    # Channel 2: tenant tightens above the new platform default (18 -> 25).
    # Allowed by only-tighten.
    cases.append(_try_write(db,
        channel="2-tenant-tighten", scope="class_weights", key="pii",
        value=25, tenant_id=TENANT_BANK, expected_blocked=False,
    ))

    # Channel 2: tenant attempts to LOOSEN (below current platform 18).
    # Blocked by only-tighten.
    cases.append(_try_write(db,
        channel="2-tenant-loosen", scope="class_weights", key="pii",
        value=10, tenant_id=TENANT_BANK, expected_blocked=True,
    ))

    # Channel 3a: signed rec proposes tenant-tightening to 30 (above 18).
    # Routes via set_override(tenant_id=BANK). Allowed.
    cases.append(_try_write(db,
        channel="3-signed-rec-tenant-tighten", scope="class_weights", key="pii",
        value=30, tenant_id=TENANT_BANK, expected_blocked=False,
    ))

    # Channel 3b: signed rec proposes tenant-LOOSENING to 5 (below 18).
    # This is the key witness — channel 3 routed at tenant level goes
    # through the SAME only-tighten guard as channel 2. Lemma survives.
    cases.append(_try_write(db,
        channel="3-signed-rec-tenant-loosen", scope="class_weights", key="pii",
        value=5, tenant_id=TENANT_BANK, expected_blocked=True,
    ))

    # Channel 3c: signed rec at platform level attempts to LOWER platform
    # default. Defense-in-depth (2026-05): platform-level writes default
    # to only-tighten; a compromised collector key cannot silently lower
    # the platform default unless the caller passes
    # allow_platform_decrease=True explicitly.
    cases.append(_try_write(db,
        channel="3-signed-rec-platform-lower", scope="class_weights", key="pii",
        value=12, tenant_id=None, expected_blocked=True,
    ))

    # Header
    print(f"{'Channel':<34} {'Target':<10} {'Val':<5} {'ExpBlk':<7} {'ActBlk':<7} {'OK'}")
    print("-" * 70)
    all_ok = True
    for c in cases:
        mark = "yes" if c["match"] else "FAIL"
        if not c["match"]:
            all_ok = False
        print(f"{c['channel']:<34} {c['target']:<10} {c['value']:<5} "
              f"{'yes' if c['expected_blocked'] else 'no':<7} "
              f"{'yes' if c['actual_blocked'] else 'no':<7} {mark}")
    print("-" * 70)

    # Final composed state
    w0 = _effective(db, tenant_id=None)
    wt = _effective(db, tenant_id=TENANT_BANK)
    print()
    print(f"Final platform default W_0(pii) = {w0}")
    print(f"Final tenant effective W_t(pii) = {wt}  (BANK)")
    lemma_holds = wt >= w0
    print(f"Lemma 1 (W_t >= W_0):  {'HOLDS' if lemma_holds else 'VIOLATED'}  ({wt} >= {w0})")
    print()
    print("WITNESS SOUND" if (all_ok and lemma_holds) else "WITNESS FAILED")
    return 0 if (all_ok and lemma_holds) else 1


if __name__ == "__main__":
    sys.exit(main())
