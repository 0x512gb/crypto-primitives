"""Tests for EIP-712 typed data hashing."""

from crypto_primitives.eip712 import (
    encode_type,
    type_hash,
    domain_separator,
    hash_typed_data,
)


# Example from EIP-712 spec: Mail struct
MAIL_TYPES = {
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"},
    ],
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person"},
        {"name": "contents", "type": "string"},
    ],
}


class TestEncodeType:
    def test_simple_type(self):
        types = {
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"},
            ]
        }
        result = encode_type("Person", types)
        assert result == "Person(string name,address wallet)"

    def test_type_with_reference(self):
        result = encode_type("Mail", MAIL_TYPES)
        # Mail references Person, so Person is appended
        assert (
            result
            == "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        )


class TestTypeHash:
    def test_type_hash_is_32_bytes(self):
        result = type_hash("Mail", MAIL_TYPES)
        assert len(result) == 32

    def test_deterministic(self):
        h1 = type_hash("Mail", MAIL_TYPES)
        h2 = type_hash("Mail", MAIL_TYPES)
        assert h1 == h2


class TestDomainSeparator:
    def test_basic_domain(self):
        domain = {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        }
        result = domain_separator(domain)
        assert len(result) == 32

    def test_minimal_domain(self):
        domain = {"name": "Test"}
        result = domain_separator(domain)
        assert len(result) == 32


class TestHashTypedData:
    def test_full_hash(self):
        domain = {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
        }
        message = {
            "from": {
                "name": "Alice",
                "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
            },
            "to": {
                "name": "Bob",
                "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
            },
            "contents": "Hello, Bob!",
        }
        result = hash_typed_data(domain, "Mail", MAIL_TYPES, message)
        assert len(result) == 32
        # Result should be deterministic
        assert hash_typed_data(domain, "Mail", MAIL_TYPES, message) == result
