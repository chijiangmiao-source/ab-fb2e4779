"""Pure-stdlib cryptographic primitives.

- Ed25519 signing/verification implemented from RFC 8032 (extended twisted
  Edwards coordinates, no external dependencies).
- Canonical UTF-8 JSON serialization used for every digest/signature input.
- Strict JSON parsing (rejects invalid UTF-8, duplicate keys, NaN/Infinity).
"""

from __future__ import annotations

import hashlib
import json

# --------------------------------------------------------------------------
# Canonical / strict JSON
# --------------------------------------------------------------------------


class JsonError(ValueError):
    """Raised when input bytes are not acceptable canonical JSON material."""


def canonical(obj) -> bytes:
    """Canonical UTF-8 JSON: sorted keys, no whitespace, unescaped Unicode."""
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def strict_loads(raw: bytes):
    """Parse bytes as strict UTF-8 JSON.

    Rejects undecodable UTF-8, duplicate object keys and non-JSON constants
    (NaN/Infinity). Returns the decoded object.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise JsonError("request body must be raw bytes")
    try:
        text = bytes(raw).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise JsonError(f"body is not valid UTF-8: {exc}") from exc

    def _no_duplicates(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise JsonError(f"duplicate object key: {key!r}")
            obj[key] = value
        return obj

    def _no_constant(name):
        raise JsonError(f"invalid JSON constant: {name}")

    try:
        return json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant
        )
    except json.JSONDecodeError as exc:
        raise JsonError(f"invalid JSON: {exc}") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Ed25519 (RFC 8032)
# --------------------------------------------------------------------------

_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow((_D * y * y + 1) % _Q, _Q - 2, _Q) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x & 1:
        x = _Q - x
    return x


_BY = (4 * pow(5, _Q - 2, _Q)) % _Q
_BX = _xrecover(_BY)

# Points in extended twisted Edwards coordinates (X, Y, Z, T), x=X/Z, y=Y/Z.
_B = (_BX % _Q, _BY % _Q, 1, (_BX * _BY) % _Q)
_IDENTITY = (0, 1, 1, 0)


def _point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _Q
    b = ((y1 + x1) * (y2 + x2)) % _Q
    c = (2 * _D * t1 * t2) % _Q
    d = (2 * z1 * z2) % _Q
    e = (b - a) % _Q
    f = (d - c) % _Q
    g = (d + c) % _Q
    h = (b + a) % _Q
    return ((e * f) % _Q, (g * h) % _Q, (f * g) % _Q, (e * h) % _Q)


def _scalarmult(point, e: int):
    result = _IDENTITY
    addend = point
    while e > 0:
        if e & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        e >>= 1
    return result


def _encode_point(point) -> bytes:
    x, y, z, _t = point
    zinv = pow(z, _Q - 2, _Q)
    xa = (x * zinv) % _Q
    ya = (y * zinv) % _Q
    out = bytearray(ya.to_bytes(32, "little"))
    out[31] |= (xa & 1) << 7
    return bytes(out)


def _decode_point(data: bytes):
    if len(data) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = data[31] >> 7
    if y >= _Q:
        raise ValueError("y coordinate out of range")
    x = _xrecover(y)
    if (x & 1) != sign:
        x = _Q - x
    if x == 0 and sign:
        raise ValueError("invalid point encoding")
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q != 0:
        raise ValueError("point not on curve")
    return (x, y, 1, (x * y) % _Q)


def _prune(scalar: bytes) -> int:
    buf = bytearray(scalar)
    buf[0] &= 248
    buf[31] &= 63
    buf[31] |= 64
    return int.from_bytes(buf, "little")


def ed25519_public_key(seed: bytes) -> bytes:
    """Derive the 32-byte public key for a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    digest = _sha512(seed)
    return _encode_point(_scalarmult(_B, _prune(digest[:32])))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Produce a deterministic 64-byte Ed25519 signature."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    digest = _sha512(seed)
    a = _prune(digest[:32])
    prefix = digest[32:]
    public = _encode_point(_scalarmult(_B, a))
    r = int.from_bytes(_sha512(prefix + message), "little") % _L
    encoded_r = _encode_point(_scalarmult(_B, r))
    k = int.from_bytes(_sha512(encoded_r + public + message), "little") % _L
    s = (r + k * a) % _L
    return encoded_r + s.to_bytes(32, "little")


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    """Return True iff ``signature`` is a valid Ed25519 signature."""
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        point_a = _decode_point(public)
        point_r = _decode_point(signature[:32])
    except ValueError:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(signature[:32] + public + message), "little") % _L
    left = _scalarmult(_B, s)
    right = _point_add(point_r, _scalarmult(point_a, k))
    return _encode_point(left) == _encode_point(right)


# --------------------------------------------------------------------------
# Hex helpers
# --------------------------------------------------------------------------


def hex_decode(value, expected_len: int, what: str) -> bytes:
    if not isinstance(value, str):
        raise JsonError(f"{what} must be a hex string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise JsonError(f"{what} is not valid hex") from exc
    if len(raw) != expected_len:
        raise JsonError(f"{what} must be {expected_len} bytes")
    return raw
