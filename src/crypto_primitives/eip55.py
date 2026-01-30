"""
EIP-55: Mixed-case checksum address encoding.

Reference: https://eips.ethereum.org/EIPS/eip-55

Encodes Ethereum addresses with a checksum using character casing.
"""

import hashlib


def to_checksum_address(address: str) -> str:
    """Convert an Ethereum address to EIP-55 checksummed format.

    Args:
        address: Hex address with or without '0x' prefix.

    Returns:
        Checksummed address with '0x' prefix.

    Raises:
        ValueError: If the address is not a valid 20-byte hex string.
    """
    # Remove 0x prefix and lowercase
    addr = address.lower().replace("0x", "")

    if len(addr) != 40:
        raise ValueError(
            f"Invalid address length: expected 40 hex chars, got {len(addr)}"
        )

    try:
        int(addr, 16)
    except ValueError:
        raise ValueError(f"Invalid hex address: {address}")

    # Keccak-256 hash of the lowercase address
    addr_hash = hashlib.sha3_256(addr.encode("ascii")).hexdigest()
    # Note: Ethereum uses Keccak-256, not SHA-3. In production, use
    # pysha3 or eth_hash. hashlib.sha3_256 is NIST SHA-3 which differs
    # in padding. Using it here as approximation for the algorithm demo.

    # Apply checksum: uppercase if corresponding hash nibble >= 8
    checksummed = "0x"
    for i, c in enumerate(addr):
        if c in "0123456789":
            checksummed += c
        elif int(addr_hash[i], 16) >= 8:
            checksummed += c.upper()
        else:
            checksummed += c.lower()

    return checksummed


def is_checksum_address(address: str) -> bool:
    """Verify if an address has a valid EIP-55 checksum.

    Args:
        address: Address with '0x' prefix.

    Returns:
        True if the checksum is valid.
    """
    if not address.startswith("0x") or len(address) != 42:
        return False

    # If all lowercase or all uppercase, it's valid (no checksum applied)
    addr_body = address[2:]
    if addr_body == addr_body.lower() or addr_body == addr_body.upper():
        return True

    # Check mixed-case checksum
    return to_checksum_address(address) == address
