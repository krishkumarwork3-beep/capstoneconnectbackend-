"""Password rules: long enough, not one of the passwords attackers try first, not the phone number.

Checked when a password is chosen (sign-up, reset, and when an admin sets one). Sign-in never
checks them: older accounts keep working.
"""

import re

from app.errors import AppError
from app.security import MIN_PASSWORD_LENGTH, normalize_phone

# The most used passwords of 8+ characters in public breach lists, plus local favourites.
COMMON = frozenset(
    """
    password password1 password12 password123 password1234 passw0rd p@ssw0rd p@ssword pa$$word
    12345678 123456789 1234567890 0123456789 987654321 9876543210 11111111 00000000 12341234
    123123123 11223344 12121212 87654321 88888888 99999999 22222222 66666666 77777777 55555555
    qwertyui qwertyuiop qwerty123 qwerty1234 1qaz2wsx 1q2w3e4r 1q2w3e4r5t zaq12wsx qazwsxedc
    asdfghjk asdfghjkl zxcvbnm1 zxcvbnmm iloveyou iloveyou1 iloveyou123 abcd1234 abcdefgh
    abc12345 abc123456 aa123456 a1234567 a12345678 welcome1 welcome123 letmein1 letmein123
    sunshine princess football baseball superman batman123 starwars dragon123 monkey123
    whatever trustno1 master123 shadow123 michael1 jennifer computer internet samsung123
    changeme changeme1 default1 admin123 admin1234 administrator adminadmin root1234 test1234
    testtest test12345 secret123 qwerty12 password! welcome! india123 india1234 bharat123
    krishna123 ganesh123 sairam123 omsairam jaihind1 cricket1 cricket123 hindustan
    capstone capstone1 capstone123 capstoneconnect college1 college123 student1 student123
    engineering engineer1
    """.split()
)


# The words behind most breached passwords: "P@ssw0rd2024", "Qwerty@123", "india@2025" and the
# like are these with leetspeak, capitals and a year or symbols around them.
BASES = frozenset(
    """
    password passwd qwerty qwertyuiop asdf asdfgh asdfghjkl zxcvbnm iloveyou welcome letmein admin
    administrator india bharat cricket capstone capstoneconnect student college engineer engineering
    krishna ganesh sairam omsairam jaihind hindustan sunshine princess football baseball superman
    batman starwars dragon monkey master shadow michael jennifer computer internet samsung changeme
    default root test secret login hello freedom whatever trustno love google iphone mumbai delhi
    pune chennai kolkata bangalore hyderabad abc abcd abcdef abcdefgh
    """.split()
)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "8": "b"})
_DECORATION = "0123456789!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ "
_WALKS = ("abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm", "1234567890", "0987654321", "1qaz2wsx3edc4rfv")


def _guessable(password: str) -> bool:
    lowered = password.lower()
    if len(set(lowered)) <= 3:
        return True  # "aaaabbbb", "11112222"
    for unit in (1, 2, 3):
        if len(lowered) % unit == 0 and lowered == lowered[:unit] * (len(lowered) // unit):
            return True  # "abababab"
    if lowered.isdigit() and len(lowered) < 12:
        return True  # dates, phone-like and other short numbers
    core = lowered.strip(_DECORATION)
    for candidate in (core, core.translate(_LEET), lowered.translate(_LEET).strip(_DECORATION)):
        if candidate in BASES or candidate in COMMON:
            return True
        if len(candidate) >= 4 and any(candidate in walk or candidate in walk[::-1] for walk in _WALKS):
            return True  # keyboard and alphabet runs, with or without digits around them
    return False


def password_problem(password: str, phone: str | None = None) -> str | None:
    """Why this password can't be used, or None."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters"
    if phone:
        digits = normalize_phone(phone)
        typed = re.sub(r"\D", "", password)
        if len(typed) >= 8 and (typed in digits or digits.endswith(typed)):
            return "Don't use your phone number as your password"
    lowered = password.lower()
    if lowered in COMMON or re.fullmatch(r"(.)\1+", password) or _guessable(password):
        return "That password is too common. Pick one that is harder to guess"
    return None


def ensure_good_password(password: str, phone: str | None = None) -> None:
    problem = password_problem(password, phone)
    if problem:
        raise AppError(problem, 422)
