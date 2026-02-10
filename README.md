# crypto-primitives

Python implementations of Bitcoin/Ethereum cryptographic standards.
Built from scratch for learning — no external crypto dependencies.

## Implemented Standards

- [x] **BIP-39**: Mnemonic Code Words — generate and validate mnemonics, derive seeds
- [x] **BIP-32**: HD Wallets — master key generation, child key derivation (hardened + normal)
- [x] **BIP-44**: Multi-Account Hierarchy — standard derivation paths (m/44'/coin'/account'/change/index)
- [x] **EIP-55**: Mixed-case Checksum Addresses — encode and validate checksummed Ethereum addresses
- [x] **EIP-712**: Typed Structured Data Hashing — domain separator, struct hashing, signing digest
- [x] **EIP-2098**: Compact Signatures — compress 65-byte signatures to 64 bytes

## Project Structure

```
src/crypto_primitives/
├── bip32.py          # HD wallet key derivation
├── bip39.py          # Mnemonic generation and seed derivation
├── bip44.py          # Multi-account derivation paths
├── eip55.py          # Checksum address encoding
├── eip712.py         # Typed data hashing
├── eip2098.py        # Compact signatures
├── utils/
│   ├── base58.py     # Base58/Base58Check encoding
│   └── hmac_utils.py # HMAC-SHA512
└── wordlist/
    └── english.txt   # BIP-39 wordlist (2048 words)
```

## Usage

```python
from crypto_primitives.bip39 import generate_mnemonic, mnemonic_to_seed
from crypto_primitives.bip32 import from_seed
from crypto_primitives.bip44 import derive_address, COIN_ETH

# Generate a 12-word mnemonic
mnemonic = generate_mnemonic(128)
print(mnemonic)
# "abandon abandon abandon ..."

# Derive seed
seed = mnemonic_to_seed(mnemonic, passphrase="optional")

# Create HD wallet
master = from_seed(seed)

# Derive Ethereum address key (m/44'/60'/0'/0/0)
eth_key = derive_address(master, coin_type=COIN_ETH)
print(eth_key.public_key.hex())
```

```python
from crypto_primitives.eip55 import to_checksum_address

addr = to_checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")
print(addr)  # "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
```

```python
from crypto_primitives.eip2098 import compact_signature, expand_signature

# Compact a 65-byte signature to 64 bytes
r_compact, yps = compact_signature(r, s, v)

# Expand back
r, s, v = expand_signature(r_compact, yps)
```

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Notes

- This is an educational project — **not for production use**
- No external cryptographic dependencies (pure Python)
- secp256k1 operations use naive implementation (not constant-time)
- EIP-55 uses SHA3-256 as approximation for Keccak-256
