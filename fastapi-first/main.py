import atexit
from datetime import datetime, timedelta
from fastapi import FastAPI, status, Query, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.encoders import jsonable_encoder
from jose import JWTError, jwt
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Optional
import json
import os


SECRET_KEY = "343ee5da890554d393985ad40ee6c0bfb75517d70b5bc6dbe4657682c5a339c6"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")


users = []
app = FastAPI()
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


class Token(BaseModel):
    access_token: str
    token_type: str


class UserRegistering(BaseModel):
    login: str
    password: str
    name: str = Query(None, min_length=5, max_length=50)


class UserDB(BaseModel):
    login: str
    name: str
    hash_password: str


def save():
    with open(DB_PATH, "w") as f:
        json.dump({"users": jsonable_encoder(users)}, f, indent=2)


def load():
    users_json = None
    if os.path.exists(DB_PATH):
        with open(DB_PATH) as f:
            try:
                users_json = json.load(f)
            except Exception as e:
                print(f"Error load users DB {e}")
    if users_json:
        for user in users_json.get("users", []):
            users.append(UserDB(login=user.get("login"),
                                hash_password=user.get("hash_password"),
                                name=user.get("name", "Jone Dou")))


def get_user_by_login(login: str) -> Optional[UserDB]:
    for user in users:
        if login == user.login:
            return user


def verify_user(password: str, user: UserDB) -> bool:
    return password_context.verify(password, user.hash_password)


def user_registration(new_user: UserRegistering):
    users.append(UserDB(login=new_user.login,
                        hash_password=password_context.encrypt(new_user.password),
                        name=new_user.name))


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def validate_token(token: str = Depends(oauth2_scheme)) -> Optional[UserDB]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        true_user = get_user_by_login(payload.get("login"))
        if users is not None:
            return true_user
    except JWTError:
        print("Bad Token")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.get("/ping", status_code=200)
def ping():
    return "Hello world"


@app.get("/x2", status_code=200)
def x2(num: int):
    return num*num


@app.post("/login", response_model=Token, status_code=200)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    true_user = get_user_by_login(form_data.username)
    if true_user is not None and verify_user(form_data.password, true_user):
        access_token = create_access_token({"login": true_user.login})
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.post("/register", status_code=200)
def register(user: UserRegistering):
    true_user = get_user_by_login(user.login)
    if true_user is None:
        user_registration(user)
        return "Success"
    else:
        return "User is already registered"


@app.get("/user_info", status_code=200)
def read_user_info(curent_user: UserDB = Depends(validate_token)):
        return curent_user.name


@app.get("/remove_user", status_code=200)
def remove_user(curent_user: UserDB = Depends(validate_token)):
    users.remove(curent_user)
    return "Success"


load()
atexit.register(save)
