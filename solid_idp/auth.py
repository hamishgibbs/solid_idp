import json
import uuid
import datetime
from rdflib import Graph
from rdflib.plugins.sparql import prepareQuery
from fastapi import HTTPException, status
from authlib.jose import jwt


def init_client_keystore(client_path: str = '.db/oidc/client'):

    client_keystore_path = client_path + '/client_auth_code.json'

    with open(client_keystore_path, 'w') as f:

        json.dump({}, f)


def check_client_callback(response_type: str,
                          redirect_uri: str,
                          scope: str,
                          client_id: str,
                          code_challenge_method: str,
                          code_challenge: str):

    # Check to be sure that the redierct_uri value provided in the auth request
    # is listed in the redirect_uris array in the oidcRegistration
    g = Graph()

    g.parse(client_id, format='turtle').serialize()

    q = prepareQuery(
        '''
        SELECT ?o
        WHERE {
            ?s <http://www.w3.org/ns/solid/terms#oidcRegistration> ?o
        }
        '''
    )

    oidc_registration = []

    for row in g.query(q):
        oidc_registration.append(row)

    client_oidc_registration = json.loads(oidc_registration[0][0])

    try:

        assert redirect_uri in client_oidc_registration['redirect_uris']

    except AssertionError:

        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unable to confirm redirect URI.",
        )


def sign_jwt(header: dict, payload: dict, PRIVATE_KEY: dict):

    token = jwt.encode(header, payload, PRIVATE_KEY)

    return token


def gen_access_token(thumbprint: str,
                     webid: str,
                     client_id: str,
                     PRIVATE_KEY: str,
                     expire: int = 600):

    issued_at = int(datetime.datetime.timestamp(datetime.datetime.now()))

    token_header = {
        "alg": "ES256",
        "typ": "JWT"
    }

    token_payload = {
        "webid": webid,
        "iss": "http://127.0.0.1:8000",
        "aud": "solid",
        "cnf": {
            "jkt": thumbprint
        },
        "client_id": client_id,
        "jti": uuid.uuid4().__str__(),
        "iat": issued_at,
        "exp": issued_at + expire
    }

    token = sign_jwt(token_header, token_payload, PRIVATE_KEY)

    return token.decode('utf-8')


def gen_id_token(webid: str,
                 client_id: str,
                 PRIVATE_KEY: str,
                 expire: int = 600):

    issued_at = int(datetime.datetime.timestamp(datetime.datetime.now()))

    token_header = {
        "alg": "ES256",
        "typ": "JWT"
    }

    token_payload = {
        "sub": webid,
        "aud": client_id,
        "webid": webid,
        "iss": "http://127.0.0.1:8000",
        "jti": uuid.uuid4().__str__(),
        "iat": issued_at,
        "exp": issued_at + expire
    }

    token = sign_jwt(token_header, token_payload, PRIVATE_KEY)

    return token.decode('utf-8')


def gen_refresh_token(PRIVATE_KEY: str,
                      expire: int = 600):

    issued_at = int(datetime.datetime.timestamp(datetime.datetime.now()))

    token_header = {
        "alg": "none"
    }

    token_payload = {
        "jti": uuid.uuid4().__str__(),
        "iat": issued_at,
        "exp": issued_at + expire
    }

    token = sign_jwt(token_header, token_payload, PRIVATE_KEY)

    return token.decode('utf-8')
