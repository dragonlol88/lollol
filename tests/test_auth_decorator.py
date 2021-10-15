import pytest
import typing as t

from pydantic import BaseModel
from fastapi import FastAPI, Request, status
from fastapi.testclient import TestClient
from fastapi.security import SecurityScopes

from . import authorize_required
from . import PermissionManager
from . import LoginManager
from . import ScopeNotSpecified


required_scopes = ["user:read"]
cannot_be_permitted_scopes = ["user:write"]

manager = LoginManager("test_secret", '/auth', use_header=True)
manager.app_name = "test"

access_token = manager.create_access_token(
    data=dict(sub="uram24@42maru.com", scopes=["user:read", "user:delete"])
)

PermissionManager(manager)

app = FastAPI()


class Items(BaseModel):
    items: t.Dict[str, int]


client = TestClient(app)


@app.post("/foo")
@authorize_required
async def foo(items: Items, scopes=SecurityScopes(required_scopes)):
    return items.items


@app.post("/bar")
@authorize_required
async def bar(items: Items, request:Request, scopes=SecurityScopes(required_scopes)):
    return items.items


@app.post("/hug")
@authorize_required
async def hug(items: Items, request: str, scopes=SecurityScopes(required_scopes)):
    return items.items


@app.post("/ssi")
@authorize_required
async def ssi(items: Items, request_x: Request, scopes=SecurityScopes(required_scopes)):
    return items.items


@app.get("/lol")
@authorize_required
async def lol(items: Items, scopes=SecurityScopes(required_scopes)):
    return items.items


@app.get("/lool")
@authorize_required
async def lollol(items: Items, scopes=SecurityScopes(cannot_be_permitted_scopes)):
    return items.items


def test_non_exist_request_param():
    response = client.post("/foo",
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


def test_exist_request_param():
    response = client.post("/bar",
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


def test_exist_request_param_with_different_type():
    response = client.post("/hug",
                           params={"request":"hug"},
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


def test_exist_request_param_with_different_name():
    response = client.post("/ssi",
                           params={"request_x": "hug"},
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


def test_get_method():
    response = client.get("/lol",
                          json={"items": {"foo": 1, "bar": 2}},
                          headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


def test_scope_not_specified():
    with pytest.raises(ScopeNotSpecified):
        @app.get("/lollol")
        @authorize_required
        async def lollol(items: Items):
            return items.items


def test_scope_cannot_permitted():
    response = client.get("/lool",
                          json={"items": {"foo": 1, "bar": 2}},
                          headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.text
