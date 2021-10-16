import lollol

from pydantic import BaseModel
from fastapi import FastAPI
from fastapi.security import SecurityScopes


# secret key to decipher and encipher the token
secret_key = "test_secret"
token_url  = '/auth'


# Permission manager initialize
lollol.PermissionManager(
    lollol.LoginManager(secret_key, token_url, use_header=True)
)
app = FastAPI()

# Authorization per router
lollol.authorize_app(app, SecurityScopes(["users"]))


class Users(BaseModel):
    id: int
    name: str
    passwd: str
    email: str


users = []


def get_fake_user(user_id):
    for user in users:
        if user["user_id"] == user_id:
            return Users(users)
    return


def create_fake_user(user: Users):
    users.append(user.dict())
    return user


@app.get("/users/{user_id}")
async def get_user(user_id: str):
    user = get_fake_user(user_id)
    return user


@app.post("/users")
async def create_user(user: Users):
    user = create_fake_user(user)
    return user
