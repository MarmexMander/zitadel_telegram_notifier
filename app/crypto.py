"""Encrypt secrets and outbox payloads under the vault master key."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def _fernet_from_master(master_key: str) -> Fernet:
    """Derive a Fernet key from MASTER_KEY (any secret string or urlsafe key material)."""
    raw = master_key.encode("utf-8")
    # Accept a ready Fernet key (url-safe base64 of 32 bytes) if provided.
    try:
        if len(base64.urlsafe_b64decode(master_key.encode("ascii"))) == 32:
            return Fernet(master_key.encode("ascii"))
    except (ValueError, TypeError):
        pass

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"zitadel-telegram-notifier-v1",
        info=b"outbox-and-signing-keys",
    ).derive(raw)
    return Fernet(base64.urlsafe_b64encode(derived))


class Seal:
    """Authenticated encryption for DB-at-rest fields."""

    def __init__(self, master_key: str) -> None:
        self._fernet = _fernet_from_master(master_key)

    def encrypt(self, plaintext: str | bytes) -> bytes:
        data = plaintext if isinstance(plaintext, bytes) else plaintext.encode("utf-8")
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken as exc:
            raise ValueError("decryption failed") from exc

    def decrypt_str(self, token: bytes) -> str:
        return self.decrypt(token).decode("utf-8")


def fingerprint(secret: str) -> str:
    """Non-reversible short id for logs (never log the secret itself)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]
