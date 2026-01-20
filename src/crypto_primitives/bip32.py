"""
BIP-32: Hierarchical Deterministic Wallets.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

Implements master key generation and child key derivation (private and public).
Uses secp256k1 curve parameters.
"""

import hashlib
import hmac
import struct


# secp256k1 curve order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Version bytes for serialization
MAINNET_PRIVATE = b"\x04\x88\xad\xe4"  # xprv
MAINNET_PUBLIC = b"\x04\x88\xb2\x1e"  # xpub


def _ser32(i: int) -> bytes:
    """Serialize 32-bit unsigned integer, big-endian."""
    return struct.pack(">I", i)


def _ser256(k: int) -> bytes:
    """Serialize 256-bit integer."""
    return k.to_bytes(32, "big")


def _parse256(b: bytes) -> int:
    """Parse 256-bit integer from bytes."""
    return int.from_bytes(b, "big")


def _point(k: int) -> bytes:
    """Compute compressed public key from private key scalar.

    Uses Python's built-in pow() for modular exponentiation on secp256k1.
    """
    # secp256k1 parameters
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    def point_add(p1, p2):
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2 and y1 != y2:
            return None
        if x1 == x2:
            lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
        x3 = (lam * lam - x1 - x2) % P
        y3 = (lam * (x1 - x3) - y1) % P
        return (x3, y3)

    def scalar_multiply(k_val, point):
        result = None
        addend = point
        while k_val:
            if k_val & 1:
                result = point_add(result, addend)
            addend = point_add(addend, addend)
            k_val >>= 1
        return result

    pub = scalar_multiply(k, (GX, GY))
    if pub is None:
        raise ValueError("Invalid private key")
    x, y = pub
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + _ser256(x)


class ExtendedKey:
    """Represents a BIP-32 extended key (private or public)."""

    def __init__(
        self,
        key: bytes,
        chain_code: bytes,
        depth: int = 0,
        parent_fingerprint: bytes = b"\x00\x00\x00\x00",
        child_index: int = 0,
        is_private: bool = True,
    ):
        self.key = key
        self.chain_code = chain_code
        self.depth = depth
        self.parent_fingerprint = parent_fingerprint
        self.child_index = child_index
        self.is_private = is_private

    @property
    def public_key(self) -> bytes:
        """Get the compressed public key."""
        if self.is_private:
            return _point(_parse256(self.key))
        return self.key

    @property
    def fingerprint(self) -> bytes:
        """First 4 bytes of Hash160 of the public key."""
        pub = self.public_key
        sha = hashlib.sha256(pub).digest()
        ripe = hashlib.new("ripemd160", sha).digest()
        return ripe[:4]

    def serialize(self) -> str:
        """Serialize to Base58Check (xprv/xpub format)."""
        version = MAINNET_PRIVATE if self.is_private else MAINNET_PUBLIC
        payload = (
            version
            + bytes([self.depth])
            + self.parent_fingerprint
            + _ser32(self.child_index)
            + self.chain_code
            + (b"\x00" + self.key if self.is_private else self.key)
        )
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        from .utils.base58 import base58_encode

        return base58_encode(payload + checksum)

    def neuter(self) -> "ExtendedKey":
        """Convert private extended key to public extended key."""
        if not self.is_private:
            return self
        return ExtendedKey(
            key=self.public_key,
            chain_code=self.chain_code,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_index=self.child_index,
            is_private=False,
        )


def from_seed(seed: bytes) -> ExtendedKey:
    """Generate master extended key from seed (BIP-32).

    Args:
        seed: 16-64 bytes of seed (typically 64 bytes from BIP-39).

    Returns:
        Master extended private key.
    """
    if len(seed) < 16 or len(seed) > 64:
        raise ValueError(f"Seed must be 16-64 bytes, got {len(seed)}")

    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]

    key = _parse256(IL)
    if key == 0 or key >= N:
        raise ValueError("Invalid master key (astronomically unlikely)")

    return ExtendedKey(key=IL, chain_code=IR)


def derive_child(parent: ExtendedKey, index: int) -> ExtendedKey:
    """Derive a child key from a parent key.

    Args:
        parent: Parent extended key.
        index: Child index. >= 0x80000000 for hardened derivation.

    Returns:
        Child extended key.
    """
    hardened = index >= 0x80000000

    if hardened:
        if not parent.is_private:
            raise ValueError("Cannot derive hardened child from public key")
        data = b"\x00" + parent.key + _ser32(index)
    else:
        data = parent.public_key + _ser32(index)

    I = hmac.new(parent.chain_code, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]

    il_int = _parse256(IL)
    if il_int >= N:
        raise ValueError("Invalid child key")

    if parent.is_private:
        key_int = (il_int + _parse256(parent.key)) % N
        if key_int == 0:
            raise ValueError("Invalid child key")
        child_key = _ser256(key_int)
        is_private = True
    else:
        # Public parent -> public child (point addition)
        parent_point = parent.key  # compressed public key
        child_point_key = IL  # will need point addition
        # For public derivation we need EC point addition
        # This is complex — for now we raise
        raise NotImplementedError("Public child derivation requires EC point addition")

    return ExtendedKey(
        key=child_key,
        chain_code=IR,
        depth=parent.depth + 1,
        parent_fingerprint=parent.fingerprint,
        child_index=index,
        is_private=is_private,
    )


def derive_path(master: ExtendedKey, path: str) -> ExtendedKey:
    """Derive key at the given BIP-32 path.

    Args:
        master: Master extended key.
        path: Derivation path like "m/44'/0'/0'/0/0".

    Returns:
        Extended key at the given path.
    """
    if not path.startswith("m"):
        raise ValueError(f"Path must start with 'm', got: {path}")

    key = master
    if path == "m":
        return key

    for part in path.split("/")[1:]:
        if part.endswith("'") or part.endswith("h"):
            index = int(part[:-1]) + 0x80000000
        else:
            index = int(part)
        key = derive_child(key, index)

    return key
