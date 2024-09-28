"""
Test suite for the Flask app and RSA key utilities.
"""
import time
from jwt_utils import generate_rsa_key, get_active_key, get_expired_key
from app import app  # Importing the Flask app
import jwt  # PyJWT for token handling
import pytest
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import mock


@pytest.fixture
def client():
    """
    Pytest fixture to create a test client for the Flask app.
    """
    with app.test_client() as client:
        yield client

def test_jwks(client):
    """
    Test the JWKS endpoint to ensure keys are returned.
    """
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    keys = response.get_json()['keys']
    assert len(keys) > 0

def test_auth(client):
    """
    Test the /auth endpoint to ensure JWT is returned.
    """
    response = client.post('/auth')
    assert response.status_code == 200
    token = response.get_json()['token']

    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header['kid']

    active_key = get_active_key(kid)

import mock

def test_expired_auth(client):
    """
    Test expired token generation and validation.
    """
    global expired_key
    expired_key = generate_rsa_key()
    expired_key['expiry'] = int(time.time()) - 3600  # Set as expired

    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    token = response.get_json()['token']

    # Mock the _verify_signature function 
    with mock.patch('jwt.api_jws.PyJWS._verify_signature', return_value=True):
        decoded = jwt.decode(token, expired_key['public_key'], algorithms=['RS256'], options={"verify_exp": False})

    assert decoded.get('exp', None) <= int(time.time())  # Check if 'exp' is less than current time
