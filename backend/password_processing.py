import numpy as np
import pandas as pd
import hashlib
import requests

SECONDS_IN_YEAR = 60 * 60 * 24 * 365


def calculate_entropy(passwords):
    passwords = np.array(passwords)

    lengths = np.char.str_len(passwords)

    has_lower = np.array([any(c.islower() for c in pw) for pw in passwords])
    has_upper = np.array([any(c.isupper() for c in pw) for pw in passwords])
    has_digit = np.array([any(c.isdigit() for c in pw) for pw in passwords])
    has_symbol = np.array([any(not c.isalnum() for c in pw) for pw in passwords])

    charset = has_lower * 26 + has_upper * 26 + has_digit * 10 + has_symbol * 32

    entropy = np.where(charset > 0, lengths * np.log2(charset), 0)
    return entropy


def estimate_crack_time_vectorized(entropy, guesses_per_second=1e9):
    return np.power(2, entropy) / guesses_per_second


def check_hibp(pw: str) -> bool:
    h = hashlib.sha1()
    h.update(pw.encode("utf-8"))
    sha1_hash = h.hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")

    hashes = (line.split(":")[0] for line in response.text.splitlines())
    return suffix in hashes


def password_dataframe(passwords):
    passwords = np.array(passwords)

    entropy = calculate_entropy(passwords)
    crack_time = estimate_crack_time_vectorized(entropy)

    hibp = [check_hibp(pw) for pw in passwords]

    df = pd.DataFrame(
        {
            "password": passwords,
            "length": np.char.str_len(passwords),
            "entropy": entropy,
            "crack_time_seconds": crack_time,
            "hibp": hibp,
        }
    )

    return df
