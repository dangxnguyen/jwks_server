from flask import Flask, request, Response, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import base64
import time

app = Flask(__name__)

# Global variable to store keys data
keys = []


# Generate RSA keys or return the most recent one if it exists
def generate_keys(new_key=False):
    global keys

    # Return the most recent key if new_key is False
    if keys and not new_key:
        return keys[-1]

    # Generate new keys
    kid = f'my-key-id-{len(keys) + 1}'
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Set the expiry time to 1 hour from now
    expiry = int(time.time()) + 3600  

    # Store the keys globally
    key = (kid, private_key, public_key, expiry)
    keys.append(key)
    return key


# Handle /auth request and return a JWT 
@app.route('/auth', methods=['POST'])
def auth():
    # Get the expired query parameter from the request
    expired = request.args.get('expired')

    # Generate a new RSA key pair or use the most recent one if it exists
    kid, private_key, public_key, expiry = generate_keys(new_key=True)
    if expired:
        # Set the expiry time to 1 hour ago if expired is set
        expiry = int(time.time()) - 3600 
        # Update the most recent key data with the new expiry time
        keys[-1] = (kid, private_key, public_key, expiry)

    # Serialize the private key to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate the JWT using the private key
    token = jwt.encode(
        {'exp': expiry},
        pem_private_key,
        algorithm='RS256',
        headers={'kid': kid}
    )

    # Return the JWT as plain text
    return Response(token, mimetype='text/plain')


# Encode number to base64url format 
def to_base64url(number):
    return base64.urlsafe_b64encode(
        number.to_bytes((number.bit_length() + 7) // 8, byteorder='big')
    ).rstrip(b'=').decode('utf-8')


# Handle /.well-known/jwks.json request and return public keys in JWKS format
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    # Get the current time
    current_time = int(time.time())
    # Dictionary to store the JWKS data
    jwks = {'keys': []}
    # Loop through all key data in keys
    for kid, _, public_key, expiry in keys:
        if expiry > current_time:
            public_numbers = public_key.public_numbers()
            jwk = {
                'kid': kid,
                'alg': 'RS256',
                'kty': 'RSA',
                'use': 'sig',
                'n': to_base64url(public_numbers.n),
                'e': to_base64url(public_numbers.e)
            }
            # Append the key data to the JWKS dictionary
            jwks['keys'].append(jwk)

    # Return the JWKS data as JSON
    return jsonify(jwks)

# Run the app
if __name__ == '__main__':
    app.run(port=8080)