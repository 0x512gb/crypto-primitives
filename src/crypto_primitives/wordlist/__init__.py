"""BIP-39 wordlists."""

from pathlib import Path


def load_wordlist(language: str = "english") -> list[str]:
    """Load BIP-39 wordlist for the given language."""
    wordlist_path = Path(__file__).parent / f"{language}.txt"
    if not wordlist_path.exists():
        raise FileNotFoundError(f"Wordlist not found: {language}")
    words = wordlist_path.read_text().strip().split("\n")
    if len(words) != 2048:
        raise ValueError(f"Expected 2048 words, got {len(words)}")
    return words
