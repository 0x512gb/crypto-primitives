"""Base58 and Base58Check encoding used in Bitcoin addresses."""

import hashlib

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE = len(ALPHABET)  # 58


def base58_encode(data: bytes) -> str:
    """Encode bytes to Base58 string."""
    # Count leading zero bytes (they become '1' characters)
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break

    # Convert bytes to integer
    num = int.from_bytes(data, "big")

    # Convert integer to base58
    result = bytearray()
    while num > 0:
        num, remainder = divmod(num, BASE)
        result.append(ALPHABET[remainder])

    result.reverse()
    return "1" * leading_zeros + result.decode("ascii")


def base58_decode(s: str) -> bytes:
    """Decode Base58 string to bytes."""
    # Count leading '1' characters
    leading_ones = 0
    for c in s:
        if c == "1":
            leading_ones += 1
        else:
            break

    # Convert base58 to integer
    num = 0
    for c in s:
        num = num * BASE + ALPHABET.index(c.encode("ascii"))

    # Convert integer to bytes
    result = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""
    return b"\x00" * leading_ones + result


def _checksum(payload: bytes) -> bytes:
    """Compute 4-byte checksum (double SHA-256)."""
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def base58check_encode(version: bytes, payload: bytes) -> str:
    """Encode with version byte and checksum."""
    data = version + payload
    return base58_encode(data + _checksum(data))


def base58check_decode(s: str) -> tuple[bytes, bytes]:
    """Decode Base58Check, returns (version, payload). Raises on bad checksum."""
    data = base58_decode(s)
    payload, checksum = data[:-4], data[-4:]
    if _checksum(payload) != checksum:
        raise ValueError("Invalid Base58Check checksum")
    return payload[:1], payload[1:]
