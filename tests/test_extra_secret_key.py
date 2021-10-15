import typing as t

from pydantic import BaseModel
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from fastapi.security import SecurityScopes
from src.lollol import authorize_required
from src.lollol import PermissionManager, LoginManager


required_scopes = ["user:read"]
cannot_be_permitted_scopes = ["user:write"]
extra_secret_key = "hello"
trash_secret_key = "trash"
secret_key = "test_secret"

manager = LoginManager(secret_key+extra_secret_key, '/auth', use_header=True)
manager.app_name = "test"

access_token = manager.create_access_token(
    data=dict(sub="uram24@42maru.com", scopes=["user:read", "user:delete"])
)

manager.secret._value = secret_key

PermissionManager(manager)

app = FastAPI()


class Items(BaseModel):
    items: t.Dict[str, int]


client = TestClient(app)


@app.post("/foo")
@authorize_required
async def foo(items: Items, scopes=SecurityScopes(required_scopes)):
    return items.items


def test_extra_key():
    response = client.post("/foo",
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}", "X-EXTRA-SECRET-KEY": extra_secret_key})

    assert response.status_code == 200, response.text


def test_extra_key_false_key():
    response = client.post("/foo",
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}", "X-EXTRA-SECRET-KEY": trash_secret_key})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.text