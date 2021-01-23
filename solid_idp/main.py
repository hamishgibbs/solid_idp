
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
import os
import json
from datetime import datetime, timedelta
from typing import Optional
import db as userdb
import data as userdata

from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = "68c0d742c73a40ff258fbcffc74ec254e51b8f9746b3513cf32cd13914adde02"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

USER_METADATA = '../.db/oidc/users/users'
USER_DATA = '../data'

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


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/")
async def home():
    return {'type': 'Super API by Hamish'}


@app.get("/{username}/card")
async def get_oidc_registration(username: str):

    profile_path = USER_DATA + '/' + username + '/profile/card.ttl'

    return FileResponse(profile_path)


@app.post("/register")
async def regster(username: str = Form(default=None),
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




@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['username']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]
