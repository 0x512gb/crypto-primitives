"""
EIP-2098: Compact Signature Representation.

Reference: https://eips.ethereum.org/EIPS/eip-2098

Compacts a 65-byte ECDSA signature (r, s, v) into 64 bytes
by encoding v (yParity) in the highest bit of s.
"""


def compact_signature(r: bytes, s: bytes, v: int) -> tuple[bytes, bytes]:
    """Compact a 65-byte signature to 64 bytes (EIP-2098).

    Args:
        r: 32-byte r value.
        s: 32-byte s value.
        v: Recovery id (0 or 1, or 27/28 for legacy).

    Returns:
        Tuple of (r, yParityAndS) — each 32 bytes.

    Raises:
        ValueError: If s is not in the lower half of the curve order.
    """
    if len(r) != 32 or len(s) != 32:
        raise ValueError("r and s must be 32 bytes each")

    # Normalize v to 0 or 1
    if v >= 27:
        v = v - 27

    if v not in (0, 1):
        raise ValueError(f"Invalid v value: {v}")

    # Check that s is in the lower half (required for compact encoding)
    s_int = int.from_bytes(s, "big")
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if s_int > N // 2:
        raise ValueError(
            "s must be in the lower half of the curve order (EIP-2/BIP-62)"
        )

    # Encode yParity in the highest bit of s
    yParityAndS_int = (v << 255) | s_int
    yParityAndS = yParityAndS_int.to_bytes(32, "big")

    return r, yParityAndS


def expand_signature(r: bytes, yParityAndS: bytes) -> tuple[bytes, bytes, int]:
    """Expand a 64-byte compact signature to 65 bytes.

    Args:
        r: 32-byte r value.
        yParityAndS: 32-byte packed yParity + s.

    Returns:
        Tuple of (r, s, v) where v is 27 or 28.
    """
    if len(r) != 32 or len(yParityAndS) != 32:
        raise ValueError("r and yParityAndS must be 32 bytes each")

    yps_int = int.from_bytes(yParityAndS, "big")

    # Extract yParity from highest bit
    yParity = yps_int >> 255

    # Extract s (mask out highest bit)
    s_int = yps_int & ((1 << 255) - 1)
    s = s_int.to_bytes(32, "big")

    # Convert to legacy v (27 or 28)
    v = 27 + yParity

    return r, s, v


def signature_to_bytes(r: bytes, s: bytes, v: int) -> bytes:
    """Convert signature components to 65-byte format."""
    if v >= 27:
        v_byte = v
    else:
        v_byte = v + 27
    return r + s + bytes([v_byte])


def compact_to_bytes(r: bytes, yParityAndS: bytes) -> bytes:
    """Convert compact signature to 64 bytes."""
    return r + yParityAndS
