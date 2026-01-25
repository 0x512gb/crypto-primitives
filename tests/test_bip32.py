"""Tests for BIP-32 implementation."""

import pytest
from crypto_primitives.bip32 import from_seed, derive_child, derive_path


# BIP-32 test vector 1
# Seed: 000102030405060708090a0b0c0d0e0f
SEED_1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f")


class TestBip32MasterKey:
    def test_master_key_generation(self):
        master = from_seed(SEED_1)
        assert master.is_private
        assert master.depth == 0
        assert master.parent_fingerprint == b"\x00\x00\x00\x00"
        assert master.child_index == 0
        assert len(master.key) == 32
        assert len(master.chain_code) == 32

    def test_master_public_key(self):
        master = from_seed(SEED_1)
        pub = master.public_key
        # Compressed public key should be 33 bytes
        assert len(pub) == 33
        assert pub[0] in (0x02, 0x03)

    def test_invalid_seed_length(self):
        with pytest.raises(ValueError, match="Seed must be"):
            from_seed(b"short")

    def test_deterministic(self):
        master1 = from_seed(SEED_1)
        master2 = from_seed(SEED_1)
        assert master1.key == master2.key
        assert master1.chain_code == master2.chain_code


class TestBip32Derivation:
    def test_hardened_child(self):
        master = from_seed(SEED_1)
        child = derive_child(master, 0x80000000)  # m/0'
        assert child.depth == 1
        assert child.is_private
        assert child.child_index == 0x80000000
        assert child.parent_fingerprint == master.fingerprint

    def test_normal_child(self):
        master = from_seed(SEED_1)
        child = derive_child(master, 0)  # m/0
        assert child.depth == 1
        assert child.is_private
        assert child.child_index == 0

    def test_derive_path(self):
        master = from_seed(SEED_1)
        # m/0'/1
        child = derive_path(master, "m/0'/1")
        assert child.depth == 2
        assert child.is_private

    def test_derive_path_identity(self):
        master = from_seed(SEED_1)
        same = derive_path(master, "m")
        assert same.key == master.key

    def test_neuter(self):
        master = from_seed(SEED_1)
        pub = master.neuter()
        assert not pub.is_private
        assert pub.key == master.public_key
        assert pub.chain_code == master.chain_code

    def test_hardened_from_public_fails(self):
        master = from_seed(SEED_1)
        pub = master.neuter()
        with pytest.raises(ValueError, match="Cannot derive hardened"):
            derive_child(pub, 0x80000000)
