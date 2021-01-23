import os


def init_db(root: str = os.getcwd()):

    db_paths = [
        '.db',
        '.db/oidc',
        '.db/oidc/users',
        '.db/oidc/users/users'
    ]

    for p in db_paths:

        if not os.path.exists(p):

            os.mkdir(p)
