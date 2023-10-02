import pytest
from app import app, generate_keys, to_base64url
import json

@pytest.fixture
def client():
    app.config['TEST'] = True
    with app.test_client() as client:
        yield client

def test_generate_keys():
    kid, private_key, public_key, expiry = generate_keys()
    assert kid is not None
    assert private_key is not None
    assert public_key is not None
    assert expiry > 0

def test_to_base64url():
    number = 123456
    result = to_base64url(number)
    assert result == 'AeJA'

def test_auth(client):
    response = client.post('/auth')
    assert response.status_code == 200
    assert len(response.data) > 0

def test_jwks(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'keys' in data
    assert len(data['keys']) > 0
