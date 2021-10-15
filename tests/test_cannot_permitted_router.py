import typing as t

from pydantic import BaseModel
from fastapi import FastAPI, status, APIRouter
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
app = FastAPI()

router = authorize_router(APIRouter(), SecurityScopes(cannot_be_permitted_scopes))


class Items(BaseModel):
    items: t.Dict[str, int]


@router.get("/lol")
async def lollol(items: Items):
    return items.items

app.include_router(router)
client = TestClient(app)


def test_router_with_permission_denied():

    response = client.get("/lol",
                          json={"items": {"foo": 1, "bar": 2}},
                          headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED, response.text


