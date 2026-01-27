"""
BIP-44: Multi-Account Hierarchy for Deterministic Wallets.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

Path: m / purpose' / coin_type' / account' / change / address_index
"""

from .bip32 import ExtendedKey, derive_path

# Common coin types (SLIP-44)
COIN_BTC = 0
COIN_BTC_TESTNET = 1
COIN_ETH = 60
COIN_LTC = 2
COIN_DOGE = 3

# Purpose constants for different address types
PURPOSE_BIP44 = 44  # Legacy (P2PKH)
PURPOSE_BIP49 = 49  # SegWit wrapped (P2SH-P2WPKH)
PURPOSE_BIP84 = 84  # Native SegWit (P2WPKH)
PURPOSE_BIP86 = 86  # Taproot (P2TR)


def derive_account(
    master: ExtendedKey,
    coin_type: int = COIN_BTC,
    account: int = 0,
    purpose: int = PURPOSE_BIP44,
) -> ExtendedKey:
    """Derive an account-level extended key.

    Args:
        master: Master key (from BIP-32/39).
        coin_type: SLIP-44 coin type.
        account: Account index.
        purpose: BIP purpose (44, 49, 84, 86).

    Returns:
        Account-level extended key at m/purpose'/coin'/account'.
    """
    path = f"m/{purpose}'/{coin_type}'/{account}'"
    return derive_path(master, path)


def derive_address(
    master: ExtendedKey,
    coin_type: int = COIN_BTC,
    account: int = 0,
    change: int = 0,
    address_index: int = 0,
    purpose: int = PURPOSE_BIP44,
) -> ExtendedKey:
    """Derive an address-level extended key.

    Args:
        master: Master key.
        coin_type: SLIP-44 coin type.
        account: Account index.
        change: 0 for external (receiving), 1 for internal (change).
        address_index: Address index.
        purpose: BIP purpose.

    Returns:
        Address-level extended key at m/purpose'/coin'/account'/change/index.
    """
    path = f"m/{purpose}'/{coin_type}'/{account}'/{change}/{address_index}"
    return derive_path(master, path)


def get_path(
    purpose: int = PURPOSE_BIP44,
    coin_type: int = COIN_BTC,
    account: int = 0,
    change: int = 0,
    address_index: int = 0,
) -> str:
    """Get the BIP-44 derivation path string."""
    return f"m/{purpose}'/{coin_type}'/{account}'/{change}/{address_index}"
