"""HMAC-SHA512 utility used by BIP-32 and BIP-39."""

import hashlib
import hmac


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-SHA512."""
    return hmac.new(key, data, hashlib.sha512).digest()
