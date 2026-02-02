"""
EIP-712: Typed structured data hashing and signing.

Reference: https://eips.ethereum.org/EIPS/eip-712

Implements structured data hashing for off-chain signature verification.
Used in permit(), meta-transactions, and typed message signing.
"""

import hashlib
from typing import Any


def _keccak256(data: bytes) -> bytes:
    """Keccak-256 hash. Note: uses SHA3-256 as approximation."""
    return hashlib.sha3_256(data).digest()


def encode_type(type_name: str, types: dict[str, list[dict[str, str]]]) -> str:
    """Encode the type string for a struct.

    EIP-712 type encoding: TypeName(type1 name1,type2 name2,...)
    Referenced types are appended alphabetically.

    Args:
        type_name: The primary type name.
        types: Mapping of type names to their fields.

    Returns:
        Encoded type string.
    """
    # Find all referenced types (recursive)
    referenced = set()

    def find_refs(name: str) -> None:
        for field in types.get(name, []):
            field_type = field["type"]
            # Strip array notation
            base_type = field_type.rstrip("[]")
            if base_type in types and base_type != type_name:
                if base_type not in referenced:
                    referenced.add(base_type)
                    find_refs(base_type)

    find_refs(type_name)

    # Primary type first, then referenced types alphabetically
    result = _encode_single_type(type_name, types[type_name])
    for ref_type in sorted(referenced):
        result += _encode_single_type(ref_type, types[ref_type])

    return result


def _encode_single_type(name: str, fields: list[dict[str, str]]) -> str:
    """Encode a single type definition."""
    field_strs = ",".join(f"{f['type']} {f['name']}" for f in fields)
    return f"{name}({field_strs})"


def type_hash(type_name: str, types: dict[str, list[dict[str, str]]]) -> bytes:
    """Compute typeHash = keccak256(encodeType(typeString))."""
    encoded = encode_type(type_name, types)
    return _keccak256(encoded.encode("utf-8"))


def encode_data(
    type_name: str,
    types: dict[str, list[dict[str, str]]],
    data: dict[str, Any],
) -> bytes:
    """Encode structured data for hashing.

    Args:
        type_name: The struct type name.
        types: Type definitions.
        data: The data values.

    Returns:
        ABI-encoded data (typeHash ++ encoded fields).
    """
    encoded = type_hash(type_name, types)

    for field in types[type_name]:
        value = data[field["name"]]
        field_type = field["type"]

        if field_type == "string":
            encoded += _keccak256(value.encode("utf-8"))
        elif field_type == "bytes":
            encoded += _keccak256(
                value if isinstance(value, bytes) else bytes.fromhex(value)
            )
        elif field_type == "address":
            # Pad address to 32 bytes
            addr = value.lower().replace("0x", "")
            encoded += bytes.fromhex(addr).rjust(32, b"\x00")
        elif field_type.startswith("uint") or field_type.startswith("int"):
            encoded += value.to_bytes(32, "big")
        elif field_type == "bool":
            encoded += (1 if value else 0).to_bytes(32, "big")
        elif field_type.startswith("bytes"):
            # Fixed-size bytes (bytes1 .. bytes32)
            size = int(field_type[5:])
            if isinstance(value, str):
                value = bytes.fromhex(value.replace("0x", ""))
            encoded += value.ljust(32, b"\x00")
        elif field_type in types:
            # Nested struct
            encoded += hash_struct(field_type, types, value)
        else:
            raise ValueError(f"Unsupported type: {field_type}")

    return encoded


def hash_struct(
    type_name: str,
    types: dict[str, list[dict[str, str]]],
    data: dict[str, Any],
) -> bytes:
    """Hash a struct: keccak256(encodeData(...))."""
    return _keccak256(encode_data(type_name, types, data))


def domain_separator(domain: dict[str, Any]) -> bytes:
    """Compute the EIP-712 domain separator.

    Args:
        domain: Domain fields (name, version, chainId, verifyingContract, salt).

    Returns:
        32-byte domain separator hash.
    """
    # Build EIP712Domain type based on which fields are present
    domain_fields = []
    field_order = [
        ("name", "string"),
        ("version", "string"),
        ("chainId", "uint256"),
        ("verifyingContract", "address"),
        ("salt", "bytes32"),
    ]

    for field_name, field_type in field_order:
        if field_name in domain:
            domain_fields.append({"name": field_name, "type": field_type})

    types = {"EIP712Domain": domain_fields}
    return hash_struct("EIP712Domain", types, domain)


def hash_typed_data(
    domain: dict[str, Any],
    primary_type: str,
    types: dict[str, list[dict[str, str]]],
    message: dict[str, Any],
) -> bytes:
    """Compute the final EIP-712 hash for signing.

    digest = keccak256("\x19\x01" ++ domainSeparator ++ hashStruct(message))

    Args:
        domain: EIP-712 domain parameters.
        primary_type: The primary struct type being signed.
        types: All type definitions.
        message: The message data.

    Returns:
        32-byte digest ready for signing.
    """
    ds = domain_separator(domain)
    struct_hash = hash_struct(primary_type, types, message)
    return _keccak256(b"\x19\x01" + ds + struct_hash)
