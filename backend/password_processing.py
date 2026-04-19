import math
import pandas as pd
import hashlib
import requests

SECONDS_IN_YEAR = 60 * 60 * 24 * 365


def calculate_entropy(password: str) -> float:
    charset = 0

    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 32

    if charset == 0:
        return 0

    return len(password) * math.log2(charset)


def estimate_crack_time(entropy: float, guesses_per_second=1e9) -> float:
    combinations = 2**entropy
    return combinations / guesses_per_second


def password_dataframe(passwords: list[str]) -> pd.DataFrame:
    data = []

    for pw in passwords:
        entropy = calculate_entropy(pw)
        crack_time_seconds = estimate_crack_time(entropy)

        hibp_check = False

        if check_hibp(pw):
            hibp_check = True

        data.append(
            {
                "password": pw,
                "length": len(pw),
                "entropy": entropy,
                "crack_time_seconds": crack_time_seconds,
                "hibp": hibp_check,
            }
        )

    return pd.DataFrame(data)


def check_hibp(pw: str) -> bool:
    h = hashlib.sha1()
    h.update(pw.encode("utf-8"))
    sha1_hash = h.hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

    hashes = (line.split(":")[0] for line in response.text.splitlines())

    return suffix in hashes
