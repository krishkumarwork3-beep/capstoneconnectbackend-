"""Field-level encryption (AES-256-GCM) and blind indexes (HMAC-SHA256) for personal data at rest.

What is encrypted, and what deliberately is not, is listed in SECURITY.md ("Field encryption").

- Keys come from the environment only: FIELD_ENCRYPTION_KEYS="<id>:<base64 of 32 bytes>,..."
  (the first is used to encrypt; the others still decrypt, for rotation) and BLIND_INDEX_KEY (a
  separate 32-byte key). Neither is ever in the repository (beyond the development defaults,
  which app.check_config refuses in production) nor in any browser bundle.
- Each value gets a random 96-bit nonce. The additional authenticated data binds the ciphertext
  to its table, column and row id, so a value copied into another row or column fails to decrypt.
- Stored as "enc:<key id>:<base64(nonce + ciphertext + tag)>". Decryption fails closed: a
  tampered, truncated, moved or unknown-key value raises, it never returns garbage or plaintext.
- Blind index: HMAC-SHA256 of the normalized value with the blind-index key, for exact-match
  lookups and uniqueness (phone numbers) without storing the value.

This is protection at rest (a stolen database dump or backup), not end-to-end encryption: the API
decrypts to serve its users. There is deliberately no encryption in browser code (its key would be
public).
"""

import base64
import hashlib
import hmac
import os
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import get_settings

PREFIX = "enc:"
NONCE_BYTES = 12


class FieldCryptoError(ValueError):
    """A value that is not a valid ciphertext for this place (tampered, moved, unknown key)."""


def _key_bytes(encoded: str, what: str) -> bytes:
    try:
        key = base64.b64decode(encoded.strip(), validate=True)
    except ValueError as exc:
        raise FieldCryptoError(f"{what} is not base64") from exc
    if len(key) != 32:
        raise FieldCryptoError(f"{what} must be 32 bytes (AES-256), got {len(key)}")
    return key


@lru_cache(maxsize=8)
def _parse_keys(spec: str) -> tuple[str, dict[str, bytes]]:
    keys: dict[str, bytes] = {}
    active = ""
    for part in (p.strip() for p in spec.split(",") if p.strip()):
        key_id, _, encoded = part.partition(":")
        if not key_id or not key_id.isalnum() or len(key_id) > 16 or key_id in keys:
            raise FieldCryptoError("FIELD_ENCRYPTION_KEYS: each entry is <id>:<base64 key>, ids unique and alphanumeric")
        keys[key_id] = _key_bytes(encoded, f"FIELD_ENCRYPTION_KEYS[{key_id}]")
        active = active or key_id
    if not keys:
        raise FieldCryptoError("FIELD_ENCRYPTION_KEYS is empty")
    return active, keys


def keys() -> tuple[str, dict[str, bytes]]:
    """(active key id, every key by id)."""
    return _parse_keys(get_settings().field_encryption_keys)


def aad(table: str, column: str, row_id: str) -> bytes:
    return f"capconnect|{table}|{column}|{row_id}".encode()


def encrypt(plaintext: str, table: str, column: str, row_id: str) -> str:
    if not row_id:
        raise FieldCryptoError(f"{table}.{column}: a row id is needed before encrypting")
    key_id, all_keys = keys()
    nonce = os.urandom(NONCE_BYTES)
    sealed = AESGCM(all_keys[key_id]).encrypt(nonce, plaintext.encode("utf-8"), aad(table, column, row_id))
    return f"{PREFIX}{key_id}:{base64.b64encode(nonce + sealed).decode()}"


def decrypt(stored: str, table: str, column: str, row_id: str) -> str:
    """The plaintext, or FieldCryptoError. An empty string stays empty (nothing to hide)."""
    if stored == "":
        return ""
    if not isinstance(stored, str) or not stored.startswith(PREFIX):
        raise FieldCryptoError(f"{table}.{column} of {row_id} is not encrypted")
    key_id, _, body = stored[len(PREFIX):].partition(":")
    key = keys()[1].get(key_id)
    if key is None:
        raise FieldCryptoError(f"{table}.{column} of {row_id}: unknown key id {key_id!r}")
    try:
        raw = base64.b64decode(body, validate=True)
        return AESGCM(key).decrypt(raw[:NONCE_BYTES], raw[NONCE_BYTES:], aad(table, column, row_id)).decode("utf-8")
    except Exception as exc:  # noqa: BLE001 - InvalidTag, bad base64, short input: all mean "not ours"
        raise FieldCryptoError(f"{table}.{column} of {row_id} failed to decrypt") from exc


def key_id_of(stored: str | None) -> str | None:
    if not stored or not stored.startswith(PREFIX):
        return None
    return stored[len(PREFIX):].partition(":")[0]


@lru_cache(maxsize=4)
def _blind_key(encoded: str) -> bytes:
    return _key_bytes(encoded, "BLIND_INDEX_KEY")


def blind_index(value: str) -> str:
    """HMAC-SHA256 (hex) of an already-normalized value, with its own key."""
    return hmac.new(_blind_key(get_settings().blind_index_key), value.encode("utf-8"), hashlib.sha256).hexdigest()


def phone_hash(phone: str) -> str:
    """The blind index of a phone number however it was written ("+91 98765 43210", "9876543210")."""
    from app.security import normalize_phone

    return blind_index(normalize_phone(phone))


def is_sealed_for(stored: str | None, table: str, column: str, row_id: str) -> bool:
    """True when `stored` is empty/None or a ciphertext that decrypts for exactly this place.
    Plaintext that merely starts with "enc:" is not sealed (the old LIKE 'enc:%' check let it
    through)."""
    if stored is None or stored == "":
        return True
    try:
        decrypt(stored, table, column, row_id)
        return True
    except FieldCryptoError:
        return False
