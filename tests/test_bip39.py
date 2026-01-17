"""Tests for BIP-39 implementation using official test vectors."""

import pytest
from crypto_primitives.bip39 import (
    entropy_to_mnemonic,
    validate_mnemonic,
    mnemonic_to_seed,
)

# Official BIP-39 test vectors (English)
# From: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
TEST_VECTORS = [
    {
        "entropy": "00000000000000000000000000000000",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "seed": "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
    },
    {
        "entropy": "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "mnemonic": "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "seed": "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
    },
    {
        "entropy": "80808080808080808080808080808080",
        "mnemonic": "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "seed": "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
    },
]


class TestBip39Mnemonic:
    @pytest.mark.parametrize("vector", TEST_VECTORS)
    def test_entropy_to_mnemonic(self, vector):
        entropy = bytes.fromhex(vector["entropy"])
        result = entropy_to_mnemonic(entropy)
        assert result == vector["mnemonic"]

    @pytest.mark.parametrize("vector", TEST_VECTORS)
    def test_validate_mnemonic(self, vector):
        assert validate_mnemonic(vector["mnemonic"]) is True

    def test_validate_invalid_mnemonic(self):
        # Wrong word
        assert (
            validate_mnemonic(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon wrong"
            )
            is False
        )

    def test_validate_wrong_length(self):
        assert validate_mnemonic("abandon abandon abandon") is False


class TestBip39Seed:
    @pytest.mark.parametrize("vector", TEST_VECTORS)
    def test_mnemonic_to_seed(self, vector):
        # Test vectors use "TREZOR" as passphrase
        seed = mnemonic_to_seed(vector["mnemonic"], passphrase="TREZOR")
        assert seed.hex() == vector["seed"]

    def test_seed_length(self):
        seed = mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        assert len(seed) == 64  # 512 bits

    def test_different_passphrase_different_seed(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed1 = mnemonic_to_seed(mnemonic, "")
        seed2 = mnemonic_to_seed(mnemonic, "my passphrase")
        assert seed1 != seed2
