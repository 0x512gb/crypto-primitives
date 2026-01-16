"""
BIP-39: Mnemonic code for generating deterministic keys.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
"""

import hashlib
import os
import unicodedata
from .wordlist import load_wordlist


def generate_entropy(strength: int = 128) -> bytes:
    """Generate random entropy.

    Args:
        strength: Entropy bits. Must be 128, 160, 192, 224, or 256.

    Returns:
        Random bytes of the specified strength.
    """
    if strength not in (128, 160, 192, 224, 256):
        raise ValueError(
            f"Invalid strength: {strength}. Must be 128-256 in steps of 32."
        )
    return os.urandom(strength // 8)


def _checksum_bits(entropy: bytes) -> str:
    """Compute checksum bits from entropy."""
    h = hashlib.sha256(entropy).digest()
    cs_bits = len(entropy) * 8 // 32
    bits = bin(int.from_bytes(h, "big"))[2:].zfill(256)
    return bits[:cs_bits]


def entropy_to_mnemonic(entropy: bytes, language: str = "english") -> str:
    """Convert entropy bytes to mnemonic sentence.

    Args:
        entropy: 16-32 bytes of entropy.
        language: Wordlist language (default: english).

    Returns:
        Space-separated mnemonic words.
    """
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError(f"Invalid entropy length: {len(entropy)} bytes")

    wordlist = load_wordlist(language)

    entropy_bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(len(entropy) * 8)
    checksum = _checksum_bits(entropy)
    all_bits = entropy_bits + checksum

    words = []
    for i in range(0, len(all_bits), 11):
        index = int(all_bits[i : i + 11], 2)
        words.append(wordlist[index])

    return " ".join(words)


def generate_mnemonic(strength: int = 128, language: str = "english") -> str:
    """Generate a new mnemonic sentence.

    Args:
        strength: Entropy bits (128=12 words, 256=24 words).
        language: Wordlist language.

    Returns:
        Space-separated mnemonic words.
    """
    entropy = generate_entropy(strength)
    return entropy_to_mnemonic(entropy, language)


def validate_mnemonic(mnemonic: str, language: str = "english") -> bool:
    """Validate a mnemonic sentence.

    Checks that all words are in the wordlist and the checksum is correct.
    """
    wordlist = load_wordlist(language)
    words = mnemonic.strip().split()

    if len(words) not in (12, 15, 18, 21, 24):
        return False

    # Convert words to indices
    try:
        indices = [wordlist.index(w) for w in words]
    except ValueError:
        return False

    # Convert indices to binary (11 bits each)
    bits = "".join(bin(idx)[2:].zfill(11) for idx in indices)

    # Split into entropy and checksum
    cs_len = len(words) // 3  # checksum length in bits
    entropy_bits = bits[:-cs_len]
    checksum_bits = bits[-cs_len:]

    # Reconstruct entropy bytes
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")

    # Verify checksum
    expected_cs = _checksum_bits(entropy)
    return checksum_bits == expected_cs


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Derive a 512-bit seed from mnemonic using PBKDF2.

    Args:
        mnemonic: Space-separated mnemonic words.
        passphrase: Optional passphrase (BIP-39 "25th word").

    Returns:
        64-byte seed for BIP-32 master key generation.
    """
    # NFKD normalization as per BIP-39 spec
    mnemonic_normalized = unicodedata.normalize("NFKD", mnemonic)
    passphrase_normalized = unicodedata.normalize("NFKD", passphrase)

    # Salt is "mnemonic" + passphrase
    salt = "mnemonic" + passphrase_normalized

    # PBKDF2 with 2048 iterations of HMAC-SHA512
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic_normalized.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=2048,
        dklen=64,
    )
