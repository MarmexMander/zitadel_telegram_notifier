"""Signature verification against pkg/actions/signing.go v4.16.0 semantics."""

from __future__ import annotations

import time

import pytest

from app.signature import (
    NoValidSignatureError,
    NotSignedError,
    TooOldError,
    compute_signature_header,
    validate_payload,
)


PAYLOAD = b'{"hello":"world"}'
KEY_A = "signing-key-a"
KEY_B = "signing-key-b"


def test_valid_signature() -> None:
    ts = int(time.time())
    header = compute_signature_header(ts, PAYLOAD, KEY_A)
    validate_payload(PAYLOAD, header, [KEY_A], now=float(ts))


def test_bad_signature() -> None:
    ts = int(time.time())
    header = compute_signature_header(ts, PAYLOAD, KEY_A)
    with pytest.raises(NoValidSignatureError):
        validate_payload(PAYLOAD, header, [KEY_B], now=float(ts))


def test_tampered_body() -> None:
    ts = int(time.time())
    header = compute_signature_header(ts, PAYLOAD, KEY_A)
    with pytest.raises(NoValidSignatureError):
        validate_payload(b'{"hello":"nope"}', header, [KEY_A], now=float(ts))


def test_stale_timestamp() -> None:
    ts = int(time.time()) - 301
    header = compute_signature_header(ts, PAYLOAD, KEY_A)
    with pytest.raises(TooOldError):
        validate_payload(PAYLOAD, header, [KEY_A], tolerance_seconds=300, now=time.time())


def test_within_tolerance_boundary() -> None:
    ts = int(time.time()) - 300
    header = compute_signature_header(ts, PAYLOAD, KEY_A)
    # Exactly at the Go boundary: age == tolerance is accepted (> only).
    validate_payload(PAYLOAD, header, [KEY_A], tolerance_seconds=300, now=float(ts + 300))


def test_missing_header() -> None:
    with pytest.raises(NotSignedError):
        validate_payload(PAYLOAD, None, [KEY_A])


def test_rotation_overlap_accepts_previous_or_active() -> None:
    ts = int(time.time())
    # Zitadel may sign with either key during overlap; header can carry multiple v1.
    header_prev = compute_signature_header(ts, PAYLOAD, KEY_A)
    header_new = compute_signature_header(ts, PAYLOAD, KEY_B)
    header_both = compute_signature_header(ts, PAYLOAD, KEY_A, KEY_B)

    keys = [KEY_B, KEY_A]  # active + previous
    validate_payload(PAYLOAD, header_prev, keys, now=float(ts))
    validate_payload(PAYLOAD, header_new, keys, now=float(ts))
    validate_payload(PAYLOAD, header_both, keys, now=float(ts))


def test_rotation_overlap_rejects_unknown_key() -> None:
    ts = int(time.time())
    header = compute_signature_header(ts, PAYLOAD, "other-key")
    with pytest.raises(NoValidSignatureError):
        validate_payload(PAYLOAD, header, [KEY_A, KEY_B], now=float(ts))


def test_empty_keys_fail_closed() -> None:
    ts = int(time.time())
    header = compute_signature_header(ts, PAYLOAD, KEY_A)
    with pytest.raises(NoValidSignatureError):
        validate_payload(PAYLOAD, header, [], now=float(ts))
