import typing as t

from pydantic import BaseModel
from fastapi import Request, APIRouter
from fastapi.testclient import TestClient
from fastapi.security import SecurityScopes

from . import PermissionManager
from . import authorize_router
from . import LoginManager

required_scopes = ["user:read"]
cannot_be_permitted_scopes = ["user:write"]

manager = LoginManager("test_secret", '/auth', use_header=True)
manager.app_name = "test"

access_token = manager.create_access_token(
    data=dict(sub="uram24@42maru.com", scopes=["user:read", "user:delete"])
)

PermissionManager(manager)

router = APIRouter()


class Items(BaseModel):
    items: t.Dict[str, int]


router = authorize_router(router, SecurityScopes(required_scopes))
client = TestClient(router)


@router.post("/foo")
async def foo(items: Items):
    return items.items


@router.post("/bar")
async def bar(items: Items, request: Request):
    return items.items


@router.post("/hug")
async def hug(items: Items, request_h: Request):
    return items.items


@router.post("/fob")
async def fob(items: Items, request: str):
    return items.items


def test_simple_router():
    response = client.post("/foo",
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


def test_simple_router_with_request():
    response = client.post("/bar",
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


def test_simple_router_with_different_request_name():
    response = client.post("/hug",
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


def test_simple_router_with_same_request_name():
    response = client.post("/fob",
                           params={"request":"x"},
                           json={"items": {"foo": 1, "bar": 2}},
                           headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200, response.text


