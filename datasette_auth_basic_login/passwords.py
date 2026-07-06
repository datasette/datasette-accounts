"""Password hashing.

The synchronous ``hash_password`` / ``verify_password`` are copied verbatim from
``datasette-auth-passwords`` (PBKDF2-HMAC-SHA256, 480 000 iterations, stdlib only).
Request handlers must never call the sync functions directly — a single 480k
iteration hash is ~100-300ms of CPU and would block the whole asyncio event loop.
Use the ``a``-prefixed async wrappers, which run the KDF in a thread executor.
"""

import asyncio
import base64
import hashlib
import secrets

ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 480000

# Bounds enforced on create / reset / change (see 03-authentication.md).
# password_min_length is configurable; the max is fixed — an unbounded
# attacker-controlled input into the KDF is a needless DoS vector.
PASSWORD_MAX_LENGTH = 1024


def hash_password(password, salt=None, iterations=ITERATIONS):
    if salt is None:
        salt = secrets.token_hex(16)
    assert salt and isinstance(salt, str) and "$" not in salt
    assert isinstance(password, str)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations
    )
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return "{}${}${}${}".format(ALGORITHM, iterations, salt, b64_hash)


def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    password_hash = password_hash.strip()
    algorithm, iterations, salt, b64_hash = password_hash.split("$", 3)
    iterations = int(iterations)
    assert algorithm == ALGORITHM
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)


# Module-level constant in the same format, generated once. Used to spend one
# PBKDF2 verification on the unknown-username / disabled-account login paths so
# response timing cannot be used to enumerate which accounts exist.
DUMMY_HASH = (
    "pbkdf2_sha256$480000$ccc3fdd3b88af3d2d754c2f72fd3cb0d$"
    "U6c8/F4O/lnhx4sPj94obLTsIc07WEtmN7uaKimy8wI="
)


async def averify_password(password, password_hash):
    """Async wrapper — runs the KDF off the event loop."""
    return await asyncio.to_thread(verify_password, password, password_hash)


async def ahash_password(password, salt=None, iterations=ITERATIONS):
    """Async wrapper — runs the KDF off the event loop."""
    return await asyncio.to_thread(hash_password, password, salt, iterations)


async def averify_dummy(password):
    """Spend one verification against DUMMY_HASH (constant-timing decoy)."""
    return await averify_password(password, DUMMY_HASH)


class PasswordLengthError(ValueError):
    """Raised when a proposed password violates the configured length bounds."""


def check_password_length(password: str, min_length: int) -> None:
    if not isinstance(password, str) or len(password) < min_length:
        raise PasswordLengthError(f"Password must be at least {min_length} characters")
    if len(password) > PASSWORD_MAX_LENGTH:
        raise PasswordLengthError(
            f"Password must be at most {PASSWORD_MAX_LENGTH} characters"
        )
