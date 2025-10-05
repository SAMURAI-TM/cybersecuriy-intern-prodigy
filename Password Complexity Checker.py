
import re
import math
import time
import sys
import getpass
import secrets
import string

# -------------------- Configuration & small built-in dictionary --------------------
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123",
    "football", "monkey", "letmein", "iloveyou", "admin", "welcome", "login",
    "princess", "solo", "passw0rd", "starwars"
}

QWERTY_ROWS = [
    "1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
]

LEET_TABLE = str.maketrans("430157$!@5", "aeoit7s!!s")  # crude map (not perfect)


# -------------------- Utility helpers --------------------
def human_time(seconds):
    if seconds < 1:
        return f"{seconds:.3f} seconds"
    minute = 60
    hour = minute * 60
    day = hour * 24
    year = day * 365
    if seconds < minute:
        return f"{seconds:.1f} seconds"
    if seconds < hour:
        return f"{seconds/minute:.1f} minutes"
    if seconds < day:
        return f"{seconds/hour:.1f} hours"
    if seconds < year:
        return f"{seconds/day:.1f} days"
    return f"{seconds/year:.1f} years"


def color_text(s, level):
    codes = {"ok": "\033[92m", "warn": "\033[93m", "bad": "\033[91m", "info": "\033[94m", "end": "\033[0m"}
    return f"{codes.get(level, '')}{s}{codes['end']}"


# -------------------- Pattern detectors --------------------
def has_sequence(password, min_len=3):
    pw = password.lower()
    for i in range(len(pw) - min_len + 1):
        substr = pw[i:i + min_len + 1]
        if all(ord(substr[j + 1]) - ord(substr[j]) == 1 for j in range(len(substr) - 1)) or \
           all(ord(substr[j]) - ord(substr[j + 1]) == 1 for j in range(len(substr) - 1)):
            return True
    return False


def has_keyboard_pattern(password, min_len=3):
    pw = password.lower()
    for row in QWERTY_ROWS:
        for i in range(len(row) - min_len + 1):
            seq = row[i:i + min_len + 1]
            if seq in pw or seq[::-1] in pw:
                return True
    return False


def longest_repeated_run(password):
    max_run = 1
    curr = 1
    for i in range(1, len(password)):
        if password[i] == password[i - 1]:
            curr += 1
            if curr > max_run:
                max_run = curr
        else:
            curr = 1
    return max_run


def contains_common_substring(password, wordset):
    pw = password.lower()
    for w in wordset:
        if len(w) >= 3 and w in pw:
            return w
    return None


def leet_to_plain(s):
    replace_map = {
        '4': 'a', '3': 'e', '0': 'o', '1': 'l', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i'
    }
    out = "".join(replace_map.get(ch, ch) for ch in s.lower())
    return out


def estimate_entropy(password):
    pool = 0
    lowers = any(c.islower() for c in password)
    uppers = any(c.isupper() for c in password)
    digits = any(c.isdigit() for c in password)
    symbols = any(not c.isalnum() for c in password)

    if lowers: pool += 26
    if uppers: pool += 26
    if digits: pool += 10
    if symbols:
        pool += 32

    if pool == 0:
        return 0.0

    # naive entropy
    entropy = math.log2(pool) * len(password)

    # penalties for weak patterns
    penalty_bits = 0.0

    # penalty: contains common substring (dictionary word)
    common = contains_common_substring(password, COMMON_PASSWORDS)
    if common:
        # subtract bits proportional to common word length
        penalty_bits += len(common) * 2.5

    # leet check
    pl = leet_to_plain(password)
    if pl != password.lower():
        if contains_common_substring(pl, COMMON_PASSWORDS):
            penalty_bits += 8

    # sequence and keyboard pattern penalty
    if has_sequence(password):
        penalty_bits += 6
    if has_keyboard_pattern(password):
        penalty_bits += 6

    # repeated characters heavy penalty
    lr = longest_repeated_run(password)
    if lr >= 3:
        penalty_bits += (lr - 2) * 2.0

    # If password is exactly a common password, set entropy very low
    if password.lower() in COMMON_PASSWORDS or pl in COMMON_PASSWORDS:
        entropy = 10.0
        penalty_bits = 8.0

    # ensure no negative
    entropy = max(0.0, entropy - penalty_bits)
    return entropy


def compute_score(password):
    entropy = estimate_entropy(password)

    # variety score: presence of categories
    variety = 0
    variety += 1 if any(c.islower() for c in password) else 0
    variety += 1 if any(c.isupper() for c in password) else 0
    variety += 1 if any(c.isdigit() for c in password) else 0
    variety += 1 if any(not c.isalnum() for c in password) else 0
    variety_score = variety * 10  # up to 40

    # length bonus
    length_bonus = min(20, max(0, (len(password) - 8) * 2))  # up to +20

    # map entropy to a 0-60 range: 60 bits or more => full 60
    entropy_score = min(60, entropy * 0.9)  # scaling factor to fit range

    raw = entropy_score + variety_score + length_bonus

    # penalties
    penalties = 0
    if contains_common_substring(password, COMMON_PASSWORDS):
        penalties += 20
    if has_sequence(password):
        penalties += 8
    if has_keyboard_pattern(password):
        penalties += 8
    if longest_repeated_run(password) >= 4:
        penalties += 6

    score = int(max(0, min(100, raw - penalties)))
    return score, entropy, {
        "variety": variety,
        "entropy_score": entropy_score,
        "variety_score": variety_score,
        "length_bonus": length_bonus,
        "penalties": penalties
    }


# -------------------- Crack time estimates --------------------
def crack_time_estimates(entropy_bits):
    # guesses ~ 2^entropy
    guesses = 2 ** entropy_bits if entropy_bits < 200 else float('inf')
    speeds = {
        "Online (100 guesses/sec)": 100,
        "Offline (1e6 guesses/sec)": 1e6,
        "GPU cluster (1e10 guesses/sec)": 1e10,
        "Massive cluster (1e12 guesses/sec)": 1e12
    }
    times = {}
    for label, speed in speeds.items():
        if guesses == float('inf'):
            times[label] = ">> infinite"
        else:
            seconds = guesses / speed
            times[label] = human_time(seconds)
    return times


# -------------------- Suggestions --------------------
def suggestions(password):
    s = []
    if len(password) < 8:
        s.append("Make it at least 8 characters long (longer is better).")
    if not any(c.isupper() for c in password):
        s.append("Add uppercase letters (A-Z).")
    if not any(c.islower() for c in password):
        s.append("Add lowercase letters (a-z).")
    if not any(c.isdigit() for c in password):
        s.append("Include digits (0-9).")
    if not any(not c.isalnum() for c in password):
        s.append("Include special characters (e.g., !@#$%).")
    if contains_common_substring(password, COMMON_PASSWORDS):
        s.append("Avoid dictionary words or common passwords (e.g., 'password', '123456').")
    if has_sequence(password):
        s.append("Avoid sequential characters (like 'abcd' or '1234').")
    if has_keyboard_pattern(password):
        s.append("Avoid simple keyboard patterns like 'qwerty' or 'asdf'.")
    if longest_repeated_run(password) >= 3:
        s.append("Avoid long repeated characters (e.g., 'aaaa').")
    if len(s) == 0:
        s.append("Good job — your password looks strong. Consider increasing length for extra security.")
    return s


# -------------------- Generator --------------------
def generate_password(length=16, use_upper=True, use_digits=True, use_symbols=True):
    pool = string.ascii_lowercase
    if use_upper:
        pool += string.ascii_uppercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += "!@#$%^&*()-_=+[]{};:,.<>/?"
    # ensure at least one of each selected type
    while True:
        pwd_chars = [secrets.choice(pool) for _ in range(length)]
        pwd = "".join(pwd_chars)
        # ensure variety
        if (not use_upper or any(c.isupper() for c in pwd)) and \
           (not use_digits or any(c.isdigit() for c in pwd)) and \
           (not use_symbols or any(not c.isalnum() for c in pwd)):
            return pwd


# -------------------- Main interactive UI --------------------
def assess_password_interactive():
    print("\nAdvanced Password Strength Checker")
    print("1) Test a password")
    print("2) Generate a strong password")
    print("3) Exit")
    choice = input("Choose (1/2/3): ").strip()
    if choice == "1":
        # hide input
        pwd = getpass.getpass("Enter password to evaluate (input hidden): ")
        score, entropy, breakdown = compute_score(pwd)
        times = crack_time_estimates(entropy)
        print("\n--- Analysis ---")
        # score bar
        bar_len = 30
        filled = int(bar_len * score / 100)
        bar = "[" + "#" * filled + "-" * (bar_len - filled) + "]"
        rating = ""
        if score < 30:
            rating = color_text("Very Weak", "bad")
        elif score < 50:
            rating = color_text("Weak", "warn")
        elif score < 70:
            rating = color_text("Fair", "info")
        elif score < 85:
            rating = color_text("Strong", "ok")
        else:
            rating = color_text("Very Strong", "ok")

        print(f"Score: {score}% {bar} => {rating}")
        print(f"Estimated entropy: {entropy:.1f} bits")
        print("\nCrack-time estimates (rough):")
        for k, v in times.items():
            print(f"  - {k}: {v}")

        print("\nAdvice:")
        for s in suggestions(pwd):
            print("  -", s)

        print("\nInternal breakdown (debug info):")
        print(f"  Variety types: {breakdown['variety']} (lower/upper/digit/symbol)")
        print(f"  Entropy score contribution: {breakdown['entropy_score']:.1f}")
        print(f"  Variety score contribution: {breakdown['variety_score']}")
        print(f"  Length bonus: {breakdown['length_bonus']}")
        print(f"  Penalties applied: {breakdown['penalties']}")
        print("\nTip: Use a long passphrase (3+ random words + symbols) or generate a secure password.\n")

    elif choice == "2":
        try:
            length = int(input("Desired length (recommended >= 12): ").strip() or "16")
            use_upper = input("Include uppercase? (Y/n): ").strip().lower() != "n"
            use_digits = input("Include digits? (Y/n): ").strip().lower() != "n"
            use_symbols = input("Include symbols? (Y/n): ").strip().lower() != "n"
            pwd = generate_password(length=length, use_upper=use_upper, use_digits=use_digits, use_symbols=use_symbols)
            print("\nGenerated password (store it safely):")
            print(color_text(pwd, "info"))
            # show its assessment too
            score, entropy, _ = compute_score(pwd)
            print(f"\nEstimated strength: {score}% — entropy {entropy:.1f} bits")
        except Exception as ex:
            print("Error:", ex)
    else:
        print("Goodbye.")
        return


if __name__ == "__main__":
    try:
        while True:
            assess_password_interactive()
            again = input("\nDo you want to evaluate another? (y/n): ").strip().lower()
            if again != "y":
                print("Bye — stay secure!")
                break
    except KeyboardInterrupt:
        print("\nInterrupted. Bye!")
