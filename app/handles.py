"""Telegram handle normalization from Zitadel args.nickName."""

from __future__ import annotations

import re

_HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{5,32}$")


class InvalidHandleError(ValueError):
    pass


def normalize_handle(raw: str | None) -> str:
    """
    Strip leading @, casefold, validate 5–32 [A-Za-z0-9_].

    Raises InvalidHandleError when empty or invalid.
    """
    if raw is None:
        raise InvalidHandleError("nickName is missing")
    handle = raw.strip().lstrip("@").casefold()
    if not handle:
        raise InvalidHandleError("nickName is empty")
    if not _HANDLE_RE.match(handle):
        raise InvalidHandleError("nickName is not a valid Telegram username")
    return handle
