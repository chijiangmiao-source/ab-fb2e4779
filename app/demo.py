"""Built-in exercise packages (演练包).

Keys are derived from fixed seeds so the demo root is stable across restarts;
item identifiers embed a fresh random nonce on every generation so repeated
demonstrations never collide with the single-use leaf ledger.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone

from .chain import format_time, item_digest
from .crypto import canonical, ed25519_public_key, ed25519_sign

DEMO_ROOT_SEED = hashlib.sha256(b"station-demo-root-v1").digest()
DEMO_OPS_SEED = hashlib.sha256(b"station-demo-ops-v1").digest()
DEMO_LEAF_SEED = hashlib.sha256(b"station-demo-leaf-v1").digest()

DEMO_ROOT_KEY = ed25519_public_key(DEMO_ROOT_SEED).hex()


def _sign_item(seed: bytes, payload: dict) -> dict:
    return {
        "payload": payload,
        "public_key": ed25519_public_key(seed).hex(),
        "signature": ed25519_sign(seed, canonical(payload)).hex(),
    }


def _payload(
    issuer,
    delegate,
    delegate_key,
    devices,
    commands,
    not_before,
    not_after,
    item_id,
    parent_digest,
):
    return {
        "issuer": issuer,
        "delegate": delegate,
        "delegate_key": delegate_key,
        "devices": devices,
        "commands": commands,
        "not_before": not_before,
        "not_after": not_after,
        "item_id": item_id,
        "parent_digest": parent_digest,
    }


def _build_chain(now: datetime, expired: bool = False):
    nonce = os.urandom(8).hex()
    if expired:
        t0 = format_time(now - timedelta(days=30))
        t1 = format_time(now - timedelta(days=7))
        mid_t0, mid_t1 = t0, t1
        leaf_t0, leaf_t1 = t0, t1
    else:
        t0 = format_time(now - timedelta(days=1))
        t1 = format_time(now + timedelta(days=180))
        mid_t0 = format_time(now - timedelta(hours=12))
        mid_t1 = format_time(now + timedelta(days=90))
        leaf_t0 = format_time(now - timedelta(hours=1))
        leaf_t1 = format_time(now + timedelta(days=30))

    ops_key = ed25519_public_key(DEMO_OPS_SEED).hex()
    leaf_key = ed25519_public_key(DEMO_LEAF_SEED).hex()

    root = _sign_item(
        DEMO_ROOT_SEED,
        _payload(
            "root-authority",
            "ops-team",
            ops_key,
            ["pump-01", "pump-02", "valve-07", "sensor-3"],
            ["restart", "status", "calibrate", "wipe"],
            t0,
            t1,
            f"root-{nonce}",
            None,
        ),
    )
    middle = _sign_item(
        DEMO_OPS_SEED,
        _payload(
            "ops-team",
            "duty-officer",
            leaf_key,
            ["pump-01", "valve-07"],
            ["restart", "status"],
            mid_t0,
            mid_t1,
            f"ops-{nonce}",
            item_digest(root),
        ),
    )
    leaf = _sign_item(
        DEMO_LEAF_SEED,
        _payload(
            "duty-officer",
            "actuator-gateway",
            "00" * 32,
            ["pump-01"],
            ["restart"],
            leaf_t0,
            leaf_t1,
            f"leaf-{nonce}",
            item_digest(middle),
        ),
    )
    return [root, middle, leaf]


def _revocation_for(item: dict) -> dict:
    payload = {
        "type": "revocation",
        "target_digest": item_digest(item),
        "reason": "演练：上级主体凭据疑似泄露",
        "issued_at": format_time(datetime.now(timezone.utc) - timedelta(minutes=5)),
    }
    return {
        "payload": payload,
        "public_key": DEMO_ROOT_KEY,
        "signature": ed25519_sign(DEMO_ROOT_SEED, canonical(payload)).hex(),
    }


def build_scenarios() -> dict:
    now = datetime.now(timezone.utc)
    request = {"device": "pump-01", "command": "restart", "params": {"delay_seconds": 5}}

    scenarios = {}

    scenarios["valid"] = {
        "note": "有效三级委托链，请求在叶级范围内，可成功执行。",
        "package": {"chain": _build_chain(now), "revocations": []},
        "request": dict(request),
    }

    tampered_chain = _build_chain(now)
    tampered_chain[2]["payload"]["commands"] = ["restart", "wipe"]
    scenarios["tampered"] = {
        "note": "叶级已签字段被事后改动（命令集合被扩大），签名验证必然失败。",
        "package": {"chain": tampered_chain, "revocations": []},
        "request": dict(request),
    }

    scenarios["out_of_scope"] = {
        "note": "委托链有效，但请求命令 wipe 超出叶级命令集合。",
        "package": {"chain": _build_chain(now), "revocations": []},
        "request": {"device": "pump-01", "command": "wipe", "params": {}},
    }

    scenarios["expired"] = {
        "note": "委托链各级签名有效，但有效窗口已过。",
        "package": {"chain": _build_chain(now, expired=True), "revocations": []},
        "request": dict(request),
    }

    revoked_chain = _build_chain(now)
    scenarios["revoked"] = {
        "note": "委托链有效，但中间级携带根签发的有效撤销声明。",
        "package": {
            "chain": revoked_chain,
            "revocations": [_revocation_for(revoked_chain[1])],
        },
        "request": dict(request),
    }

    return scenarios
