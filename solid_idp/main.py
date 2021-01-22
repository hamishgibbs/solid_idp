
# auth flow

# SQL db of login credentials (username & password)
# redirect to solid_idp domain to login
# redirect to "XXX would like to access XXX"
# redirect to redirect uri (stored in "redirect_uris" of solid:oidcRegistration)
# check client secret with stored secret initiated by client
# Grant tokens to client
# client uses token to gain access to thing
# list of scope types understood - contacts.read contacts.write etc.
#


from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from passlib.context import CryptContext

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()


@app.get("/")
async def root():
    return {"message": "Solid IdP Provider"}


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user
