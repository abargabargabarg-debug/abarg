import pyotp
from werkzeug.security import generate_password_hash, check_password_hash

def hash_pass(password):
    """Securely hashes a password."""
    return generate_password_hash(password)

def verify_pass(hash_str, password):
    """Checks if a password matches the hash."""
    return check_password_hash(hash_str, password)

def generate_2fa_secret():
    """Generates a random 32-character secret for 2FA."""
    return pyotp.random_base32()

def get_totp_uri(username, secret):
    """Generates the URI for the QR code."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Main Abarg Messenger")