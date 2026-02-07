"""Tests for EIP-2098 compact signatures."""

import pytest
from crypto_primitives.eip2098 import (
    compact_signature,
    expand_signature,
    signature_to_bytes,
    compact_to_bytes,
)


# Example signature values
R = bytes.fromhex("68a020a209d3d56c46f38cc50a33f704f4a9a10a59377f8dd762ac66910e9b90")
S = bytes.fromhex("7e865ad05c4035ab5792787d4a0297a43617ae897930a6fe4d822b8faea52064")
V = 27  # yParity = 0


class TestCompactSignature:
    def test_compact_v27(self):
        r, yps = compact_signature(R, S, V)
        assert r == R
        assert len(yps) == 32
        # Since v=27 (parity=0), highest bit should be 0
        assert yps[0] < 0x80

    def test_compact_v28(self):
        r, yps = compact_signature(R, S, 28)
        assert r == R
        # Since v=28 (parity=1), highest bit should be 1
        assert yps[0] >= 0x80

    def test_compact_v0(self):
        r, yps = compact_signature(R, S, 0)
        assert yps[0] < 0x80

    def test_compact_v1(self):
        r, yps = compact_signature(R, S, 1)
        assert yps[0] >= 0x80


class TestExpandSignature:
    def test_roundtrip_v27(self):
        r, yps = compact_signature(R, S, V)
        r2, s2, v2 = expand_signature(r, yps)
        assert r2 == R
        assert s2 == S
        assert v2 == 27

    def test_roundtrip_v28(self):
        r, yps = compact_signature(R, S, 28)
        r2, s2, v2 = expand_signature(r, yps)
        assert r2 == R
        assert s2 == S
        assert v2 == 28


class TestByteConversions:
    def test_standard_bytes(self):
        result = signature_to_bytes(R, S, V)
        assert len(result) == 65
        assert result[:32] == R
        assert result[32:64] == S
        assert result[64] == 27

    def test_compact_bytes(self):
        r, yps = compact_signature(R, S, V)
        result = compact_to_bytes(r, yps)
        assert len(result) == 64
        assert result[:32] == R
        assert result[32:] == yps

    def test_compact_saves_one_byte(self):
        standard = signature_to_bytes(R, S, V)
        r, yps = compact_signature(R, S, V)
        compact = compact_to_bytes(r, yps)
        assert len(standard) - len(compact) == 1


class TestEdgeCases:
    def test_invalid_r_length(self):
        with pytest.raises(ValueError, match="32 bytes"):
            compact_signature(b"short", S, V)

    def test_invalid_v(self):
        with pytest.raises(ValueError, match="Invalid v"):
            compact_signature(R, S, 2)

    def test_high_s_rejected(self):
        # s in upper half of curve order should be rejected
        N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        high_s = (N - 1).to_bytes(32, "big")
        with pytest.raises(ValueError, match="lower half"):
            compact_signature(R, high_s, V)
