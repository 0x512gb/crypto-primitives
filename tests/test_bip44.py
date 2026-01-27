"""Tests for BIP-44 derivation paths."""

from crypto_primitives.bip44 import (
    get_path,
    derive_address,
    COIN_BTC,
    COIN_ETH,
    PURPOSE_BIP84,
)
from crypto_primitives.bip32 import from_seed


SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class TestBip44Path:
    def test_default_path(self):
        assert get_path() == "m/44'/0'/0'/0/0"

    def test_ethereum_path(self):
        assert get_path(coin_type=COIN_ETH) == "m/44'/60'/0'/0/0"

    def test_segwit_path(self):
        assert get_path(purpose=PURPOSE_BIP84) == "m/84'/0'/0'/0/0"

    def test_second_account(self):
        assert get_path(account=1) == "m/44'/0'/1'/0/0"

    def test_change_address(self):
        assert get_path(change=1) == "m/44'/0'/0'/1/0"

    def test_address_index(self):
        assert get_path(address_index=5) == "m/44'/0'/0'/0/5"


class TestBip44Derivation:
    def test_derive_btc_address(self):
        master = from_seed(SEED)
        key = derive_address(master, coin_type=COIN_BTC)
        assert key.depth == 5
        assert key.is_private

    def test_derive_eth_address(self):
        master = from_seed(SEED)
        key = derive_address(master, coin_type=COIN_ETH)
        assert key.depth == 5
        assert key.is_private

    def test_different_accounts_different_keys(self):
        master = from_seed(SEED)
        key0 = derive_address(master, account=0)
        key1 = derive_address(master, account=1)
        assert key0.key != key1.key
