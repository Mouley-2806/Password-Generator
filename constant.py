import string
from pathlib import Path

COMMON_WEAK_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "admin", "letmein", "welcome", "monkey", "12345678", "iloveyou",
    "111111", "sunshine", "princess", "dragon", "master", "login",
    "pass", "test", "1234", "12345", "1234567", "123123",
}

DEFAULT_LENGTH       = 16
LOWERCASE            = string.ascii_lowercase
UPPERCASE            = string.ascii_uppercase
DIGITS               = string.digits
SYMBOLS              = string.punctuation

AMBIGUOUS_CHARS      = "ILO01l"   # FIX: original missed lowercase 'l'
HIBP_API_URL         = "https://api.pwnedpasswords.com/range/"
HIBP_USER_AGENT      = "Password-Generator-Project"

BASE_DIR                   = Path(__file__).parent.parent
LOCAL_WEAK_PASSWORDS_FILE  = BASE_DIR / "weak_passwords_hashes.txt"


def initialize_local_storage():
    """Create the local weak-password hash store if it doesn't exist."""
    if not LOCAL_WEAK_PASSWORDS_FILE.exists():
        try:
            LOCAL_WEAK_PASSWORDS_FILE.touch()
            print(f"  Local weak-password store created at: {LOCAL_WEAK_PASSWORDS_FILE}")
        except Exception as e:
            print(f"  Error creating file: {e}")


def get_local_weak_hashes() -> set:
    """Return the set of SHA-256 hashes stored in the local weak-password file."""
    hashes: set = set()
    try:
        if LOCAL_WEAK_PASSWORDS_FILE.exists():
            with open(LOCAL_WEAK_PASSWORDS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        hashes.add(line)
    except Exception as e:
        print(f"  Error reading local weak-password file: {e}")
    return hashes


def add_to_local_weak_hashes(password_hash: str):
    """Append a SHA-256 hash to the local weak-password file."""
    try:
        with open(LOCAL_WEAK_PASSWORDS_FILE, "a", encoding="utf-8") as f:
            f.write(password_hash + "\n")
    except Exception as e:
        print(f"  Could not save password hash: {e}")
