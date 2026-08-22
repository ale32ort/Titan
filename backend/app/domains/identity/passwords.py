from pwdlib import PasswordHash

# Configure the recommended password hashing algorithm (Argon2)
password_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """
    Convert a plaintext password into a secure hash.
    """
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verify a plaintext password against a stored hash.
    """
    return password_hasher.verify(password, password_hash)