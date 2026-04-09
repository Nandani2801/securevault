import base64


def encrypt_password(password: str) -> str:
    # A04: base64 is encoding, NOT encryption — trivially reversible
    return base64.b64encode(password.encode()).decode()


def decrypt_password(encoded: str) -> str:
    try:
        return base64.b64decode(encoded.encode()).decode()
    except Exception:
        return encoded
