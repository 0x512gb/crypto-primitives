"""Download BIP-39 English wordlist."""

import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
OUTPUT = (
    Path(__file__).parent.parent
    / "src"
    / "crypto_primitives"
    / "wordlist"
    / "english.txt"
)


def main():
    print(f"Downloading BIP-39 wordlist to {OUTPUT}")
    urllib.request.urlretrieve(URL, OUTPUT)
    words = OUTPUT.read_text().strip().split("\n")
    print(f"Downloaded {len(words)} words")


if __name__ == "__main__":
    main()
