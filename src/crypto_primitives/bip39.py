"""
BIP-39: Mnemonic code for generating deterministic keys.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
"""

import hashlib
import os
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
    # Number of checksum bits = entropy_bits / 32
    cs_bits = len(entropy) * 8 // 32
    # Convert first byte(s) of hash to binary and take cs_bits
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

    # Convert entropy to binary string
    entropy_bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(len(entropy) * 8)
    checksum = _checksum_bits(entropy)
    all_bits = entropy_bits + checksum

    # Split into 11-bit groups and map to words
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
