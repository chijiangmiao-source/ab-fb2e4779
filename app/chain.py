"""Delegation-chain evaluation.

A delegation package is canonical UTF-8 JSON of the form::

    {
      "chain": [
        {"payload": {...}, "public_key": "<hex>", "signature": "<hex>"},
        ...
      ],
      "revocations": [
        {"payload": {...}, "public_key": "<hex>", "signature": "<hex>"}
      ]
    }

Each payload commits to its parent via ``parent_digest`` and may only narrow
the device set, command set and validity window of its parent. The verdict is
determined jointly by the trusted root key, the chain digest, the leaf item
identifier and the request payload.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .crypto import (
    JsonError,
    canonical,
    ed25519_verify,
    hex_decode,
    sha256_hex,
)

MAX_CHAIN_LEN = 8
MAX_LIST_ITEMS = 64
MAX_STR_LEN = 256
ZERO_DIGEST = "0" * 64

PAYLOAD_FIELDS = {
    "issuer",
    "delegate",
    "delegate_key",
    "devices",
    "commands",
    "not_before",
    "not_after",
    "item_id",
    "parent_digest",
}
ITEM_FIELDS = {"payload", "public_key", "signature"}
PACKAGE_FIELDS = {"chain", "revocations"}
REVOCATION_REQUIRED = {"type", "target_digest", "issued_at"}
REVOCATION_OPTIONAL = {"reason", "not_after"}
REQUEST_REQUIRED = {"device", "command"}
REQUEST_OPTIONAL = {"params"}


def parse_time(value):
    """Parse an ISO-8601 timestamp; require an explicit timezone."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"malformed timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must carry a timezone")
    return parsed.astimezone(timezone.utc)


def format_time(moment: datetime) -> str:
    return (
        moment.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def item_digest(item: dict) -> str:
    """SHA-256 of the canonical encoding of a whole chain item."""
    return sha256_hex(canonical(item))


class Check:
    __slots__ = ("name", "ok", "detail")

    def __init__(self, name, ok, detail=""):
        self.name = name
        self.ok = ok
        self.detail = detail

    def to_dict(self):
        return {"name": self.name, "ok": self.ok, "detail": self.detail}


class EvalReport:
    """Structured result of evaluating a package plus request."""

    def __init__(self):
        self.ok = False
        self.first_error = None
        self.levels = []
        self.revocations = []
        self.request_checks = []
        self.root_key = None
        self.chain_digest = None
        self.leaf_id = None
        self.leaf_key = None
        self.verdict_key = None
        self.request_hash = None
        self.leaf_already_used = None

    def fail(self, message):
        if self.first_error is None:
            self.first_error = message

    def to_dict(self):
        return {
            "ok": self.ok,
            "first_error": self.first_error,
            "summary": {
                "root_key": self.root_key,
                "chain_digest": self.chain_digest,
                "leaf_id": self.leaf_id,
                "leaf_key": self.leaf_key,
                "verdict_key": self.verdict_key,
                "request_hash": self.request_hash,
                "leaf_already_used": self.leaf_already_used,
            },
            "levels": self.levels,
            "revocations": self.revocations,
            "request": self.request_checks,
        }


def _check_str_list(value, what, errors):
    if not isinstance(value, list) or not value:
        errors.append(f"{what} must be a non-empty list")
        return None
    if len(value) > MAX_LIST_ITEMS:
        errors.append(f"{what} has too many entries")
        return None
    seen = set()
    for entry in value:
        if (
            not isinstance(entry, str)
            or not entry
            or len(entry) > MAX_STR_LEN
        ):
            errors.append(f"{what} entries must be non-empty short strings")
            return None
        if entry in seen:
            errors.append(f"{what} contains duplicate entry {entry!r}")
            return None
        seen.add(entry)
    return value


def _validate_payload(payload, errors):
    if not isinstance(payload, dict):
        errors.append("payload must be an object")
        return None
    unknown = set(payload) - PAYLOAD_FIELDS
    if unknown:
        errors.append(f"payload has unexpected fields: {sorted(unknown)}")
        return None
    missing = PAYLOAD_FIELDS - set(payload)
    if missing:
        errors.append(f"payload is missing fields: {sorted(missing)}")
        return None
    for field in ("issuer", "delegate", "item_id"):
        if (
            not isinstance(payload[field], str)
            or not payload[field]
            or len(payload[field]) > MAX_STR_LEN
        ):
            errors.append(f"payload.{field} must be a non-empty string")
    try:
        hex_decode(payload["delegate_key"], 32, "payload.delegate_key")
    except JsonError as exc:
        errors.append(str(exc))
    devices = _check_str_list(payload["devices"], "payload.devices", errors)
    commands = _check_str_list(payload["commands"], "payload.commands", errors)
    try:
        not_before = parse_time(payload["not_before"])
        not_after = parse_time(payload["not_after"])
        if not_before >= not_after:
            errors.append("payload.not_before must be before payload.not_after")
    except ValueError as exc:
        errors.append(str(exc))
        not_before = not_after = None
    parent_digest = payload["parent_digest"]
    if parent_digest is not None:
        if not isinstance(parent_digest, str) or len(parent_digest) != 64:
            errors.append("payload.parent_digest must be null or 64 hex chars")
        else:
            try:
                bytes.fromhex(parent_digest)
            except ValueError:
                errors.append("payload.parent_digest must be hex")
    if errors:
        return None
    return {
        "issuer": payload["issuer"],
        "delegate": payload["delegate"],
        "delegate_key": payload["delegate_key"].lower(),
        "devices": devices,
        "commands": commands,
        "not_before": not_before,
        "after": not_after,
        "not_before_raw": payload["not_before"],
        "not_after_raw": payload["not_after"],
        "item_id": payload["item_id"],
        "parent_digest": parent_digest.lower() if parent_digest else None,
    }


def _validate_item(item, index, errors):
    if not isinstance(item, dict):
        errors.append(f"chain[{index}] must be an object")
        return None
    unknown = set(item) - ITEM_FIELDS
    if unknown:
        errors.append(f"chain[{index}] has unexpected fields: {sorted(unknown)}")
        return None
    missing = ITEM_FIELDS - set(item)
    if missing:
        errors.append(f"chain[{index}] is missing fields: {sorted(missing)}")
        return None
    try:
        hex_decode(item["public_key"], 32, f"chain[{index}].public_key")
        hex_decode(item["signature"], 64, f"chain[{index}].signature")
    except JsonError as exc:
        errors.append(str(exc))
    payload = _validate_payload(item["payload"], errors)
    if errors:
        return None
    return {
        "raw": item,
        "payload": payload,
        "public_key": item["public_key"].lower(),
        "signature": item["signature"].lower(),
        "digest": item_digest(item),
    }


def evaluate(package, request, trusted_roots, now=None, leaf_used_lookup=None):
    """Evaluate a delegation package and request.

    ``trusted_roots`` is a set of hex-encoded root public keys.
    ``leaf_used_lookup`` (optional) is called with the leaf key and should
    return True when the leaf credential has already driven a device.
    Returns an EvalReport; nothing is persisted here.
    """
    now = now or datetime.now(timezone.utc)
    report = EvalReport()

    # ---- structural pass -------------------------------------------------
    items = None
    revocations = []
    if not isinstance(package, dict):
        report.fail("package must be a JSON object")
    else:
        unknown = set(package) - PACKAGE_FIELDS
        missing = {"chain"} - set(package)
        if unknown:
            report.fail(f"package has unexpected fields: {sorted(unknown)}")
        elif missing:
            report.fail("package is missing 'chain'")
        else:
            chain = package["chain"]
            if (
                not isinstance(chain, list)
                or not chain
                or len(chain) > MAX_CHAIN_LEN
            ):
                report.fail(
                    f"chain must be a list of 1..{MAX_CHAIN_LEN} items"
                )
            else:
                errors = []
                items = [_validate_item(it, i, errors) for i, it in enumerate(chain)]
                if errors:
                    report.fail(errors[0])
                    items = None
            raw_revocations = package.get("revocations", [])
            if not isinstance(raw_revocations, list):
                report.fail("revocations must be a list")
            else:
                revocations = raw_revocations

    if items is None:
        return report

    report.root_key = items[0]["public_key"]
    report.chain_digest = sha256_hex(canonical(package["chain"]))
    report.leaf_id = items[-1]["payload"]["item_id"]
    report.request_hash = sha256_hex(canonical(request)) if request is not None else None
    report.leaf_key = sha256_hex(
        canonical(
            {
                "root": report.root_key,
                "chain": report.chain_digest,
                "leaf": report.leaf_id,
            }
        )
    )
    if request is not None:
        report.verdict_key = sha256_hex(
            canonical(
                {
                    "root": report.root_key,
                    "chain": report.chain_digest,
                    "leaf": report.leaf_id,
                    "request": request,
                }
            )
        )

    # ---- per-level cryptographic and narrowing checks --------------------
    previous = None
    chain_broken = False
    for index, item in enumerate(items):
        payload = item["payload"]
        checks = []

        signature_ok = ed25519_verify(
            bytes.fromhex(item["public_key"]),
            bytes.fromhex(item["signature"]),
            canonical(item["raw"]["payload"]),
        )
        checks.append(
            Check(
                "signature",
                signature_ok,
                "签名有效" if signature_ok else "签名无效或被篡改",
            )
        )

        if index == 0:
            trusted = item["public_key"] in trusted_roots
            checks.append(
                Check(
                    "root-trusted",
                    trusted,
                    "根公钥受信" if trusted else "根公钥不在受信集合",
                )
            )
            anchored = payload["parent_digest"] in (None, ZERO_DIGEST)
            checks.append(
                Check(
                    "root-anchor",
                    anchored,
                    "根项无父级绑定" if anchored else "根项不得携带父级摘要",
                )
            )
        else:
            bound = payload["parent_digest"] == previous["digest"]
            checks.append(
                Check(
                    "parent-binding",
                    bound,
                    "已绑定父项摘要" if bound else "父项摘要不匹配",
                )
            )
            subject_ok = payload["issuer"] == previous["payload"]["delegate"]
            checks.append(
                Check(
                    "subject-chain",
                    subject_ok,
                    "主体衔接正确"
                    if subject_ok
                    else "签发者与上级被委托人不一致",
                )
            )
            key_ok = item["public_key"] == previous["payload"]["delegate_key"]
            checks.append(
                Check(
                    "key-chain",
                    key_ok,
                    "密钥衔接正确" if key_ok else "公钥与上级指定不符",
                )
            )
            devices_ok = set(payload["devices"]) <= set(previous["payload"]["devices"])
            checks.append(
                Check(
                    "device-narrowing",
                    devices_ok,
                    "设备范围收窄" if devices_ok else "设备范围越界扩大",
                )
            )
            commands_ok = set(payload["commands"]) <= set(previous["payload"]["commands"])
            checks.append(
                Check(
                    "command-narrowing",
                    commands_ok,
                    "命令集合收窄" if commands_ok else "命令集合越界扩大",
                )
            )
            window_ok = (
                payload["not_before"] >= previous["payload"]["not_before"]
                and payload["after"] <= previous["payload"]["after"]
            )
            checks.append(
                Check(
                    "window-narrowing",
                    window_ok,
                    "有效窗口收窄" if window_ok else "有效窗口越界扩大",
                )
            )

        time_ok = payload["not_before"] <= now <= payload["after"]
        checks.append(
            Check(
                "time-valid",
                time_ok,
                "当前处于有效窗口"
                if time_ok
                else "委托未生效或已过期",
            )
        )

        level = {
            "index": index,
            "digest": item["digest"],
            "issuer": payload["issuer"],
            "delegate": payload["delegate"],
            "public_key": item["public_key"],
            "signature_valid": signature_ok,
            "devices": payload["devices"],
            "commands": payload["commands"],
            "not_before": payload["not_before_raw"],
            "not_after": payload["not_after_raw"],
            "item_id": payload["item_id"],
            "parent_digest": payload["parent_digest"],
            "checks": [c.to_dict() for c in checks],
        }
        report.levels.append(level)
        for check in checks:
            if not check.ok:
                report.fail(f"level {index} [{check.name}]: {check.detail}")
                chain_broken = True
        previous = item

    # ---- revocations ------------------------------------------------------
    item_digests = {item["digest"]: i for i, item in enumerate(items)}
    signer_keys = {item["public_key"] for item in items}
    for position, revocation in enumerate(revocations):
        entry = {
            "index": position,
            "valid": False,
            "target_digest": None,
            "target_level": None,
            "detail": "",
        }
        try:
            if not isinstance(revocation, dict) or set(revocation) != ITEM_FIELDS:
                raise JsonError("revocation envelope must be payload/public_key/signature")
            payload = revocation["payload"]
            if not isinstance(payload, dict):
                raise JsonError("revocation payload must be an object")
            if not REVOCATION_REQUIRED <= set(payload):
                raise JsonError("revocation payload missing required fields")
            if set(payload) - REVOCATION_REQUIRED - REVOCATION_OPTIONAL:
                raise JsonError("revocation payload has unexpected fields")
            if payload["type"] != "revocation":
                raise JsonError("revocation payload type must be 'revocation'")
            public = hex_decode(revocation["public_key"], 32, "revocation.public_key")
            signature = hex_decode(revocation["signature"], 64, "revocation.signature")
            target = payload["target_digest"]
            if not isinstance(target, str) or len(target) != 64:
                raise JsonError("target_digest must be 64 hex chars")
            target = target.lower()
            bytes.fromhex(target)
            entry["target_digest"] = target
            if not ed25519_verify(public, signature, canonical(payload)):
                raise JsonError("revocation signature invalid")
            signer = revocation["public_key"].lower()
            if signer != report.root_key and signer not in signer_keys:
                raise JsonError("revocation signer is not the root or a chain issuer")
            issued_at = parse_time(payload["issued_at"])
            if issued_at > now:
                raise JsonError("revocation issued in the future")
            if "not_after" in payload and parse_time(payload["not_after"]) < now:
                raise JsonError("revocation itself has expired")
            if target not in item_digests:
                raise JsonError("revocation targets no item of this chain")
            entry["valid"] = True
            entry["target_level"] = item_digests[target]
            entry["detail"] = "撤销声明有效"
        except (JsonError, ValueError) as exc:
            entry["detail"] = f"撤销声明无效（忽略）: {exc}"
        report.revocations.append(entry)
        if entry["valid"]:
            report.fail(
                f"level {entry['target_level']}: 委托项已被有效撤销声明撤销"
            )
            chain_broken = True

    # ---- request scope -----------------------------------------------------
    if request is None:
        report.fail("request is required")
        chain_broken = True
    else:
        leaf = items[-1]["payload"]
        req_checks = []
        if not isinstance(request, dict):
            req_checks.append(Check("request-shape", False, "请求必须是 JSON 对象"))
        else:
            unknown = set(request) - REQUEST_REQUIRED - REQUEST_OPTIONAL
            missing = REQUEST_REQUIRED - set(request)
            shape_ok = not unknown and not missing
            detail = "请求字段合法" if shape_ok else ""
            if unknown:
                detail = f"请求含未知字段: {sorted(unknown)}"
            elif missing:
                detail = f"请求缺少字段: {sorted(missing)}"
            req_checks.append(Check("request-shape", shape_ok, detail))
            if shape_ok:
                device = request["device"]
                command = request["command"]
                device_ok = isinstance(device, str) and device in leaf["devices"]
                req_checks.append(
                    Check(
                        "device-in-scope",
                        device_ok,
                        "设备在叶级范围内"
                        if device_ok
                        else f"设备 {device!r} 超出叶级范围",
                    )
                )
                command_ok = isinstance(command, str) and command in leaf["commands"]
                req_checks.append(
                    Check(
                        "command-in-scope",
                        command_ok,
                        "命令在叶级范围内"
                        if command_ok
                        else f"命令 {command!r} 越权",
                    )
                )
        report.request_checks = [c.to_dict() for c in req_checks]
        for check in req_checks:
            if not check.ok:
                report.fail(f"request [{check.name}]: {check.detail}")
                chain_broken = True

    # ---- leaf single-use status (informational during inspect) ------------
    if leaf_used_lookup is not None:
        try:
            report.leaf_already_used = bool(leaf_used_lookup(report.leaf_key))
        except Exception:
            report.leaf_already_used = None

    report.ok = not chain_broken and report.first_error is None
    return report
