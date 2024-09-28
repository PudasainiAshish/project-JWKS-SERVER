"""
Utilities for handling RSA key generation and retrieval.
"""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time
import uuid

key_store = []  # Store keys in memory


def generate_rsa_key():
    """
    Generate an RSA key pair.
    :return: Dictionary containing key information.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    kid = str(uuid.uuid4())  # Unique Key ID
    expiry = int(time.time()) + 3600  # 1 hour expiry

    key_entry = {
        'kid': kid,
        'private_key': private_key,
        'public_key': public_key,
        'expiry': expiry
    }

    key_store.append(key_entry)
    return key_entry


def get_active_key(kid):
    """
    Retrieve the active key based on Key ID (kid).
    :param kid: Key ID
    :return: Dictionary containing active key information, or None if not found.
    """
    current_time = int(time.time())
    active_keys = [key for key in key_store if key['expiry'] > current_time and key['kid'] == kid]
    return active_keys[0] if active_keys else None


def get_expired_key():
    """
    Retrieve the first expired key from the store.
    :return: Dictionary containing expired key information, or None if no expired key exists.
    """
    expired_keys = [key for key in key_store if key['expiry'] <= int(time.time())]
    return expired_keys[0] if expired_keys else None
