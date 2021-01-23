import os
import json


def init_db(path: str = os.getcwd()):

    db_paths = [
        '/.db',
        '/.db/oidc',
        '/.db/oidc/users',
        '/.db/oidc/users/users'
    ]

    for p in db_paths:

        if not os.path.exists(path + p):

            os.mkdir(path + p)


def create_user(username: str,
                hashed_password: str,
                email: str,
                full_name: str = None,
                disabled: bool = False,
                db: str = '.db/oidc/users/users'):

    user = {
        'username': username,
        'hashed_password': username,
        'email': email,
        'full_name': full_name,
        'disabled': disabled
    }

    user_fn = db + '/' + username + '.json'

    with open(user_fn, "w") as f:

        json.dump(user, f)
