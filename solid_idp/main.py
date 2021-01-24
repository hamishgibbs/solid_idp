import os
import json
from datetime import datetime, timedelta
from typing import Optional
from solid_idp import db as userdb
from solid_idp import data as userdata
from solid_idp import auth
import secrets
import hashlib
import base64

from fastapi import Depends, FastAPI, HTTPException, status, Form, Header
from fastapi.responses import RedirectResponse, FileResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from authlib.jose import jwt, JsonWebKey

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend as crypto_default_backend

# generate key pairs for the session
key = ec.generate_private_key(ec.SECP256R1(), backend=crypto_default_backend())

private_key = key.private_bytes(
    crypto_serialization.Encoding.PEM,
    crypto_serialization.PrivateFormat.PKCS8,
    crypto_serialization.NoEncryption())
public_key = key.public_key().public_bytes(
    crypto_serialization.Encoding.OpenSSH,
    crypto_serialization.PublicFormat.OpenSSH
)

IDP_PRIVATE_KEY = JsonWebKey.import_key(private_key, {'kty': 'EC'})
IDP_PUBLIC_KEY = JsonWebKey.import_key(public_key, {'kty': 'EC'})

USER_METADATA = './.db/oidc/users/users'
CLIENT_METADATA = './.db/oidc/client'
USER_DATA = './data'


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(username: str):

    user_fn = username + '.json'

    if user_fn in os.listdir(USER_METADATA):

        with open(USER_METADATA + '/' + user_fn, "r") as f:
            user_dict = json.load(f)

        return user_dict


def authenticate_user(username: str, password: str):

    user = get_user(username)

    if not user:
        return False
    if not verify_password(password, user['hashed_password']):
        return False
    return user


@app.get("/")
async def home():
    return {'message': 'I am an example SOLID IdP.'}


@app.get("/{username}/card")
async def get_oidc_registration(username: str):

    profile_path = USER_DATA + '/' + username + '/profile/card.ttl'

    return FileResponse(profile_path)


@app.post("/register")
async def register(username: str = Form(default=None),
                   password: str = Form(default=None),
                   email: str = Form(default=None),
                   full_name: str = Form(default=None),
                   disabled: bool = Form(default=None)):

    user_fn = username + '.json'

    if user_fn in os.listdir(USER_METADATA):

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    else:

        userdb.create_user(username=username,
                           hashed_password=get_password_hash(password),
                           email=email,
                           full_name=full_name,
                           disabled=disabled,
                           db=USER_METADATA)

        userdata.create_personal_profile_document(username=username,
                                                  data_path=USER_DATA,
                                                  iss='http://127.0.0.1:8000')

        return {"message": "Successfully created user."}


@app.get("/login")
async def get_login():

    return {'message': 'This is the login endpoint.'}


@app.post("/login")
async def post_login(form_data: OAuth2PasswordRequestForm = Depends()):

    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # on successful login - generate tokens here and pass them back to client
    # WebID callback URL
    # this is not the correct flow as it is not happening in the browser but
    # serves as a good example of the auth flow?

    # may need to retun the code direct from the authorize endpoint now

    return {'message': 'Successfully logged in.'}


@app.get("/.well-known/openid_configuration")
async def get_oid_configuration():

    return FileResponse('./static/openid-configuration.json')


@app.get("/authorize/")
async def authorize(response_type: str,
                    redirect_uri: str,
                    scope: str,
                    client_id: str,
                    code_challenge_method: str,
                    code_challenge: str,
                    # This does not follow a realistic implementation
                    # which would involve a redirect to the login page and
                    # proceed on successful login
                    user_username: str,
                    user_password: str):

    auth_result = auth.check_client_callback(response_type=response_type,
                                             redirect_uri=redirect_uri,
                                             scope=scope,
                                             client_id=client_id,
                                             code_challenge_method=code_challenge_method,
                                             code_challenge=code_challenge)

    if type(auth_result) is HTTPException:

        raise auth_result

    # stand-in for actual user authentication
    user = authenticate_user(user_username, user_password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # if auth is successful up to now

    client_keystore_path = CLIENT_METADATA + '/client_auth_code.json'

    with open(client_keystore_path, 'r') as f:

        client_keystore = json.loads(f.read())

    client_code = secrets.token_hex(22)

    client_keystore[client_code] = {
        "client_id": client_id,
        "code_challenge": code_challenge,
        "webid": 'http://127.0.0.1:8000/' + client_id + '/card#me',
        "response_types": response_type.split(' '),
        "scope": scope.split(' ')
    }

    with open(client_keystore_path, 'w') as f:

        json.dump(client_keystore, f)

    return RedirectResponse(redirect_uri + '?code=' + client_code)


@app.post("/token")
async def get_access_token(grant_type: str,
                           code_verifier: str,
                           code: str,
                           redirect_uri: str,
                           client_id: str,
                           DPoP: str = Header(None),
                           content_type: str = Header(None)):

    client_keystore_path = CLIENT_METADATA + '/client_auth_code.json'

    with open(client_keystore_path, 'r') as f:

        client_keystore = json.loads(f.read())

    # check to see that the client_id in the keystore corresponds
    # to the client_id from the request
    try:

        assert client_keystore[code]['client_id'] == client_id

    except AssertionError:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authorized client_id does not match supplied client_id.",
        )

    # verify that the code verifier corresponds with the code challenge
    # stored in the keystore
    try:

        challenge_checked = base64.b64encode(hashlib.sha256(code_verifier.encode('ascii')).digest())

        assert challenge_checked.decode("utf-8") == client_keystore[code]['code_challenge']

    except AssertionError:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Code challenges do not match.",
        )

    # decode JWT headers and extract public key
    dpop_token_header = base64.b64decode(DPoP.split('.')[1] + '=' * 5)
    dpop_token_header = json.loads(dpop_token_header.decode('utf-8'))
    dpop_public_key = dpop_token_header['jwk']

    try:

        # test that this is correctly checking key signature
        claims = jwt.decode(DPoP, dpop_public_key)

        claims.validate()

    except Exception:

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unable to validata DPoP Token.",
        )

    dpop_public_key = JsonWebKey.import_key(dpop_public_key, {'kty': 'EC'})
    dpop_public_key_thumbprint = dpop_public_key.thumbprint()

    all_tokens = {
        "expires_in": 600,
        "token_type": "DPoP",
        "scope": " ".join(client_keystore[code]['scope'])
    }

    access_token = auth.gen_access_token(thumbprint=dpop_public_key_thumbprint,
                                         webid=client_keystore[code]['webid'],
                                         client_id=client_id,
                                         PRIVATE_KEY=IDP_PRIVATE_KEY,
                                         expire=600)

    all_tokens['access_token'] = access_token

    if 'open_id' in client_keystore[code]['scope']:

        id_token = auth.gen_id_token(webid=client_keystore[code]['webid'],
                                     client_id=client_id,
                                     PRIVATE_KEY=IDP_PRIVATE_KEY,
                                     expire=600)

        all_tokens['id_token'] = id_token

    if 'offline_access' in client_keystore[code]['scope']:

        # save this in a persistent store to permit refresh requests
        refresh_token = auth.gen_refresh_token(PRIVATE_KEY=IDP_PRIVATE_KEY,
                                               expire=600)

        all_tokens['refresh_token'] = refresh_token

    headers = {"content-type": "application/json"}

    return JSONResponse(content=all_tokens, headers=headers)
