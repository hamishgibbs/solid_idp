from pymongo import MongoClient


def get_user(db: MongoClient,
             username: str):

    users = db.users

    if username in users.distinct('user'):

        user = users.find_one({'username': username})

        return user


def create_user(db: MongoClient,
                username: str,
                hashed_password: str,
                email: str,
                full_name: str = None,
                disabled: bool = False):

    users = db.users

    user = {
        'username': username,
        'hashed_password': hashed_password,
        'email': email,
        'full_name': full_name,
        'disabled': disabled
    }

    users.insert_one(user)
