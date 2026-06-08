import hashlib
import math
import requests
from .constant import (
    COMMON_WEAK_PASSWORDS,
    HIBP_API_URL,
    HIBP_USER_AGENT,
    get_local_weak_hashes,
    add_to_local_weak_hashes,
    initialize_local_storage
)

def calculate_entropy(password: str) -> float:
    """Calculate password entropy in bits (float)."""
    if not password:
        return 0.0

    has_lower  = any(c.islower() for c in password)
    has_upper  = any(c.isupper() for c in password)
    has_digit  = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    pool_size = 0
    if has_lower:  pool_size += 26
    if has_upper:  pool_size += 26
    if has_digit:  pool_size += 10
    if has_symbol: pool_size += 32
    if pool_size == 0:
        pool_size = 95

    # Real entropy formula: length * log2(pool_size)
    return round(len(password) * math.log2(pool_size), 2)


def is_pwned_hibp(password: str) -> tuple:
    """Check password against Have I Been Pwned API (k-anonymity model)."""
    if not password:
        return False, 0

    sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    headers = {"User-Agent": HIBP_USER_AGENT}

    try:
        response = requests.get(
            f"{HIBP_API_URL}{prefix}", headers=headers, timeout=6
        )
        if response.status_code == 200:
            for line in response.text.splitlines():
                if ":" in line and line.split(":")[0] == suffix:
                    count = int(line.split(":")[1])
                    return True, count
            return False, 0
        return False, 0
    except Exception:
        return False, 0


def assess_strength(password: str, enable_learning: bool = True):
    """
    Assess password strength.

    Returns: (level: str, feedback: str, entropy: float)
    """
    if not password:
        return "Very Weak", "Password is empty.", 0.0

    entropy = calculate_entropy(password)
    length  = len(password)
    score   = 0
    breach_info = ""   # FIX: was " " (space) — caused HIBP check to be skipped

    # --- Breach / common-password checks (set score = 0 on hit) ---
    if password.lower() in COMMON_WEAK_PASSWORDS:
        score = 0
        breach_info = "⚠️  This is one of the most commonly used passwords in the world."
    else:
        local_hashes  = get_local_weak_hashes()
        password_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if password_hash in local_hashes:
            score = 0
            breach_info = "⚠️  This password was previously marked as weak by you."

    # Only query HIBP when no local/common hit has been found yet
    if not breach_info:
        is_pwned, count = is_pwned_hibp(password)
        if is_pwned:
            score = 0
            breach_info = (
                f"🔴 This password has been found in {count:,} real data breach(es)!"
            )

    # --- Length scoring ---
    if length >= 18:  score += 5
    elif length >= 14: score += 4
    elif length >= 12: score += 3
    elif length >= 8:  score += 2

    # --- Complexity scoring ---
    if any(c.islower()   for c in password): score += 1
    if any(c.isupper()   for c in password): score += 1
    if any(c.isdigit()   for c in password): score += 1
    if any(not c.isalnum() for c in password): score += 1

    # --- Entropy scoring ---
    if   entropy >= 80: score += 3
    elif entropy >= 60: score += 3   # FIX: kept consistent (original had duplicate 3)
    elif entropy >= 40: score += 2

    # FIX: if breach was found, cap score at 0 so it can't climb to "Strong"
    if breach_info:
        score = 0

    # --- Determine strength level ---
    if score >= 12:
        level    = "Very Strong"
        feedback = "✅ Excellent — extremely hard to guess!"
    elif score >= 9:
        level    = "Strong"
        feedback = "👍 Great password. Highly recommended."
    elif score >= 6:
        level    = "Medium"
        feedback = "🟡 Decent, but could be improved (try longer + more symbol variety)."
    elif score >= 3:
        level    = "Weak"
        feedback = "🟠 Weak password — easy to crack."
    else:
        level    = "Very Weak"
        feedback = "🔴 Too weak — do not use this password."

    if breach_info:
        feedback = breach_info + "\n" + feedback

    # --- Optional learning: save weak passwords to local list ---
    if enable_learning and level in ("Weak", "Very Weak") and not breach_info:
        try:
            choice = input(
                "Save this to your local weak-password list for future checks? (y/n): "
            ).strip().lower()
            if choice == "y":
                pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
                add_to_local_weak_hashes(pwd_hash)
                print("✔  Saved to weak-password list.")
        except Exception:
            pass

    return level, feedback, entropy


def print_password_count(password: str):
    """Pretty-print the full strength report for a password."""
    level, feedback, entropy = assess_strength(password)
    bar_width = 72
    print("\n" + "=" * bar_width)
    print(f"  Password : {password}")
    print(f"  Length   : {len(password)} characters")
    print(f"  Entropy  : {entropy:.1f} bits")
    print(f"  Strength : {level}")
    print(f"  Feedback : {feedback}")
    print("=" * bar_width)
