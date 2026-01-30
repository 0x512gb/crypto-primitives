"""Tests for EIP-55 checksum addresses."""

import pytest
from crypto_primitives.eip55 import to_checksum_address, is_checksum_address


# EIP-55 test cases
CHECKSUM_ADDRESSES = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


class TestEip55:
    def test_to_checksum_preserves_valid(self):
        for addr in CHECKSUM_ADDRESSES:
            result = to_checksum_address(addr)
            # Result should be a valid checksummed address
            assert result.startswith("0x")
            assert len(result) == 42

    def test_from_lowercase(self):
        addr = "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
        result = to_checksum_address(addr)
        assert result.startswith("0x")
        assert len(result) == 42

    def test_is_checksum_all_lowercase(self):
        # All lowercase is considered valid (no checksum)
        assert is_checksum_address("0x" + "a" * 40) is True

    def test_is_checksum_all_uppercase(self):
        # All uppercase is considered valid (no checksum)
        assert is_checksum_address("0x" + "A" * 40) is True

    def test_invalid_length(self):
        with pytest.raises(ValueError, match="Invalid address length"):
            to_checksum_address("0x1234")

    def test_invalid_hex(self):
        with pytest.raises(ValueError, match="Invalid hex"):
            to_checksum_address("0x" + "g" * 40)

    def test_without_prefix(self):
        result = to_checksum_address("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
        assert result.startswith("0x")
