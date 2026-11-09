"""Bot UI localization.

Primary locale source is the Zitadel HTTP email-provider payload
(`args.preferredLanguage` / nested profile fields). Zitadel already
localizes `templateData` (subject/text/buttonText) using the user's
PreferredLanguage; that body is not retranslated here.

As of Zitadel v4.16, `mapNotifyUserToArgs` does not always include
PreferredLanguage in webhook `args` (it is used only when rendering
templates). Extraction still checks the documented payload locations so
future/custom payloads work. When absent: use the locale persisted on
the Telegram binding, else default ``en``. For unmatched ``/start``
(no Zitadel context), Telegram ``language_code`` is a last resort only.
"""

from __future__ import annotations

from typing import Any, Mapping

DEFAULT_LOCALE = "en"
SUPPORTED_LOCALES = frozenset({"en", "uk"})

# msgid → per-locale string. Add a locale by extending each entry and
# SUPPORTED_LOCALES (normalization maps en-US → en, uk-UA → uk).
_CATALOGS: dict[str, dict[str, str]] = {
    "unmatched_start": {
        "en": (
            "You are not in the system yet. "
            "Wait for an invitation from the admin."
        ),
        "uk": (
            "Вас ще немає в системі. "
            "Зачекайте на запрошення від адміністратора."
        ),
    },
    "admin_invalid_recipient": {
        "en": "Zitadel notify: invalid recipient for login={login!r}: {error}",
        "uk": (
            "Zitadel notify: некоректний отримувач для login={login!r}: {error}"
        ),
    },
    "open_link": {
        "en": "Open",
        "uk": "Відкрити",
    },
}


def normalize_locale(tag: str | None) -> str:
    """
    Normalize BCP-47-ish tags to a supported catalog key.

    ``en``, ``en-US``, ``EN_GB`` → ``en``; ``uk``, ``uk-UA`` → ``uk``.
    Unknown or empty tags fall back to ``DEFAULT_LOCALE``.
    """
    if not tag or not isinstance(tag, str):
        return DEFAULT_LOCALE
    cleaned = tag.strip().replace("_", "-")
    if not cleaned:
        return DEFAULT_LOCALE
    primary = cleaned.split("-", 1)[0].casefold()
    if primary in SUPPORTED_LOCALES:
        return primary
    return DEFAULT_LOCALE


def _coerce_lang(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    # language.Tag-like objects / accidental non-strings
    text = str(value).strip()
    return text or None


def _from_mapping(data: Mapping[str, Any]) -> str | None:
    for key in (
        "preferredLanguage",
        "PreferredLanguage",
        "preferred_language",
    ):
        found = _coerce_lang(data.get(key))
        if found is not None:
            return found
    return None


def extract_locale_tag(payload: Mapping[str, Any] | None) -> str | None:
    """
    Return the raw language tag from a Zitadel webhook payload, or None.

    Lookup order (first hit wins):
    1. ``args.preferredLanguage`` / ``PreferredLanguage`` / ``preferred_language``
    2. nested ``args.profile`` / ``args.Profile`` (same keys)
    3. top-level payload keys (same names)
    """
    if not payload:
        return None

    args = payload.get("args")
    if isinstance(args, Mapping):
        found = _from_mapping(args)
        if found is not None:
            return found
        for nest_key in ("profile", "Profile", "human", "Human"):
            nested = args.get(nest_key)
            if isinstance(nested, Mapping):
                found = _from_mapping(nested)
                if found is not None:
                    return found

    return _from_mapping(payload)


def extract_locale(payload: Mapping[str, Any] | None) -> str | None:
    """Normalized locale from payload, or None if the field is absent."""
    tag = extract_locale_tag(payload)
    if tag is None:
        return None
    return normalize_locale(tag)


def resolve_locale(
    *,
    payload: Mapping[str, Any] | None = None,
    stored: str | None = None,
    telegram_language_code: str | None = None,
) -> str:
    """
    Resolve catalog locale.

    Priority: Zitadel payload → stored binding locale → Telegram
    ``language_code`` (last resort, unmatched /start only) → ``en``.
    """
    from_payload = extract_locale(payload)
    if from_payload is not None:
        return from_payload
    if stored:
        return normalize_locale(stored)
    if telegram_language_code:
        return normalize_locale(telegram_language_code)
    return DEFAULT_LOCALE


def t(key: str, locale: str | None = None, **kwargs: Any) -> str:
    """Look up a bot-authored string; missing keys raise KeyError."""
    catalog = _CATALOGS[key]
    lang = normalize_locale(locale)
    template = catalog.get(lang) or catalog[DEFAULT_LOCALE]
    if kwargs:
        return template.format(**kwargs)
    return template
