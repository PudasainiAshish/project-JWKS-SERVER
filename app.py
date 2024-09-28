"""
Flask application to serve JWKS and handle authentication.
"""

from flask import Flask, jsonify, request
import jwt  # PyJWT
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import uuid
import base64
import time

app = Flask(__name__)

# Store generated keys
keys = []

# Function to generate RSA keys
def generate_rsa_key():
    """
    Generate an RSA key pair and store in a dictionary.
    :return: Dictionary containing private key, public key, key ID (kid), and expiry.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    kid = str(uuid.uuid4())  # Unique Key ID
    expiry = datetime.utcnow() + timedelta(days=1)  # 1 day expiry

    # Convert public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')

    return {
        "private_key": private_key,
        "public_key": public_key,
        "public_key_pem": public_key_pem,  # Store public key in PEM format
        "kid": kid,
        "expiry": expiry.timestamp(),  # Store expiry as a timestamp
    }

# Initial key generation
keys = [generate_rsa_key()]
expired_key = None  # For storing expired key when needed

def int_to_base64url(n):
    """
    Convert integer to base64 URL-encoded string.
    """
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).rstrip(b'=').decode('utf-8')

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """
    Serve JWKS (JSON Web Key Set).
    :return: JSON response containing valid keys.
    """
    jwk_keys = []
    current_time = time.time()

    for key in keys:
        if key["expiry"] > current_time:
            public_numbers = key["public_key"].public_numbers()
            jwk = {
                "kty": "RSA",
                "kid": key["kid"],
                "use": "sig",  # Use for signature verification
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e),
                "alg": "RS256"  # Algorithm used
            }
            jwk_keys.append(jwk)

    return jsonify({"keys": jwk_keys})

@app.route('/auth', methods=['POST'])
def auth():
    """
    Handle authentication and issue JWT.
    :return: JSON containing JWT.
    """
    expired = request.args.get('expired') == 'true'

    if expired:
        global expired_key
        if expired_key is None or expired_key['expiry'] > time.time():  # Only generate if there's no expired key or it's still valid
            expired_key = generate_rsa_key()
            expired_key['expiry'] = datetime.utcnow() - timedelta(days=1)  # Set as expired

        key = expired_key
        exp_time = datetime.utcnow() - timedelta(minutes=10)  # Issue token as already expired
    else:
        key = keys[0]  # Use current key
        exp_time = datetime.utcnow() + timedelta(minutes=10)  # Token expires in 10 minutes

    token = jwt.encode(
        {
            "sub": "user123",  # Mock user
            "exp": exp_time,
            "iat": datetime.utcnow(),
            "iss": "auth_server",
        },
        key["private_key"],
        algorithm="RS256",
        headers={"kid": key["kid"]}
    )

    return jsonify({"token": token})

if __name__ == '__main__':
    app.run(port=8080)
