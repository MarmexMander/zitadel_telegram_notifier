"""ZITADEL-Signature verification matching pkg/actions/signing.go (v4.16.0)."""

from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence

SIGNING_HEADER = "ZITADEL-Signature"
DEFAULT_TOLERANCE_SECONDS = 300

_PART_SEP = ","
_TIMESTAMP_KEY = "t"
_VERSION_KEY = "v1"


class SignatureError(Exception):
    """Base class for signature failures (mapped to HTTP 401)."""


class NotSignedError(SignatureError):
    pass


class InvalidHeaderError(SignatureError):
    pass


class TooOldError(SignatureError):
    pass


class NoValidSignatureError(SignatureError):
    pass


@dataclass(frozen=True)
class ParsedHeader:
    timestamp: int
    signatures: tuple[bytes, ...]


def compute_signature(timestamp: int, payload: bytes, signing_key: str) -> bytes:
    """HMAC-SHA256 over ASCII timestamp + '.' + raw body."""
    mac = hmac.new(signing_key.encode("utf-8"), digestmod=sha256)
    mac.update(str(timestamp).encode("ascii"))
    mac.update(b".")
    mac.update(payload)
    return mac.digest()


def compute_signature_header(
    timestamp: int, payload: bytes, *signing_keys: str
) -> str:
    """Build a ZITADEL-Signature header (useful for tests / fixtures)."""
    parts = [f"{_TIMESTAMP_KEY}={timestamp}"]
    for key in signing_keys:
        digest = compute_signature(timestamp, payload, key).hex()
        parts.append(f"{_VERSION_KEY}={digest}")
    return _PART_SEP.join(parts)


def parse_signature_header(header: str | None) -> ParsedHeader:
    if header is None or header == "":
        raise NotSignedError("webhook has no ZITADEL-Signature header")

    timestamp: int | None = None
    signatures: list[bytes] = []

    for pair in header.split(_PART_SEP):
        parts = pair.split("=", 1)
        if len(parts) != 2:
            raise InvalidHeaderError("webhook has invalid ZITADEL-Signature header")
        key, value = parts[0], parts[1]
        if key == _TIMESTAMP_KEY:
            try:
                timestamp = int(value)
            except ValueError as exc:
                raise InvalidHeaderError(
                    "webhook has invalid ZITADEL-Signature header"
                ) from exc
        elif key == _VERSION_KEY:
            try:
                signatures.append(bytes.fromhex(value))
            except ValueError:
                # Match Go: skip undecodable hex for v1 entries.
                continue

    if not signatures:
        raise NoValidSignatureError("no valid signature")
    if timestamp is None:
        raise InvalidHeaderError("webhook has invalid ZITADEL-Signature header")

    return ParsedHeader(timestamp=timestamp, signatures=tuple(signatures))


def validate_payload(
    payload: bytes,
    header: str | None,
    signing_keys: Sequence[str],
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> None:
    """
    Verify raw body against one or more signing keys (active + previous overlap).

    Fail closed: missing/malformed/stale/no-match all raise SignatureError.
    Multiple v1 entries in the header are allowed (any match wins).
    """
    if not signing_keys:
        raise NoValidSignatureError("no signing keys configured")

    parsed = parse_signature_header(header)
    current = time.time() if now is None else now
    # Match Go time.Since(timestamp) > tolerance (future timestamps are accepted).
    if (current - parsed.timestamp) > tolerance_seconds:
        raise TooOldError("timestamp wasn't within tolerance")

    for key in signing_keys:
        expected = compute_signature(parsed.timestamp, payload, key)
        for sig in parsed.signatures:
            if hmac.compare_digest(expected, sig):
                return

    raise NoValidSignatureError("no valid signature")
