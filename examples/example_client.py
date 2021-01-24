import secrets
import hashlib
import base64
import requests as r
import urllib

from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from authlib.jose import jwk, jwt, JsonWebKey

import uuid
import datetime
# PKCE Code Flow

# get IdP OID configuration
login_res = r.get('http://127.0.0.1:8000/.well-known/openid_configuration')

login_res.status_code
login_res.json()

# this is stored in session memory
random_secret = secrets.token_hex(10)

# ascii encode, sha256 hash, b64 encode tmp secret
code_challenge = base64.b64encode(hashlib.sha256(random_secret.encode('ascii')).digest())

# request an authorisation code from IdP
auth_endpoint = login_res.json()['authorization_endpoint']

auth_params = {'response_type': 'code',
               'redirect_uri': 'http://127.0.0.1:8001/callback',
               'scope': 'open_id profile offline_access',
               'client_id': 'http://127.0.0.1:8001/webid#this',
               'code_challenge_method': 'S256',
               'code_challenge': code_challenge,
               'user_username': 'jade',
               'user_password': 'i<3hamish'}

auth_res = r.get(auth_endpoint,
                 params=auth_params)

auth_res.status_code
auth_res.json()

auth_res.url

# code is provided in the redirect URL to the client callback
client_auth_code = urllib.parse.parse_qs(urllib.parse.urlparse(auth_res.url).query)['code'][0]

key = ec.generate_private_key(ec.SECP256R1(), backend=crypto_default_backend())

private_key = key.private_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PrivateFormat.PKCS8,
    crypto_serialization.NoEncryption())
public_key = key.public_key().public_bytes(
    crypto_serialization.Encoding.OpenSSH,
    crypto_serialization.PublicFormat.OpenSSH
)

CLIENT_PRIVATE_KEY = JsonWebKey.import_key(private_key, {'kty': 'EC'})
CLIENT_PUBLIC_KEY = JsonWebKey.import_key(public_key, {'kty': 'EC'})

dpop_token_header = {
    "alg": "ES256",
    "typ": "dpop+jwt"
}

dpop_token_payload = {
    "htu": "http://127.0.0.1:8001",
    "jwk": CLIENT_PUBLIC_KEY,
    "htm": "POST",
    "jti": uuid.uuid4().__str__(),
    "iat": int(datetime.datetime.timestamp(datetime.datetime.now()))
}


dpop_token = jwt.encode(dpop_token_header, dpop_token_payload, CLIENT_PRIVATE_KEY)

auth_headers = {
    "DPoP": dpop_token,
    "content-type": "application/x-www-form-urlencoded"
}

auth_body = {
    'grant_type': 'authorization_code',
    'code_verifier': random_secret,
    'code': client_auth_code,
    'redirect_uri': 'http://127.0.0.1:8001/callback',
    'client_id': 'http://127.0.0.1:8001/webid#this'
}


res = r.post("http://127.0.0.1:8000/token", params=auth_body, headers=auth_headers)

res.status_code
res.json()

# next steps:
# Incorporate this workflow in solid_client
# get these tokens workign with an example resource server
