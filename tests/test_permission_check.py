import asyncio
from src.lollol import PermissionManager, LoginManager

from fastapi.security import SecurityScopes




required_scopes = ["user:read"]
manager = LoginManager("test_secret", '/auth', use_header=True)
manager.app_name = "test"
access_token = manager.create_access_token(
    data=dict(sub="uram24@42maru.com", scopes=["user:read", "user:delete"])
)


class Request:
    def __init__(self, headers):
        self.headers = headers


request = Request({"Authorization": f"Bearer {access_token}"})


def async_test(coro):
    def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        loop.run_until_complete(coro(*args, **kwargs))
    return wrapper


@async_test
async def test_check_permission():
    pm = PermissionManager(manager)
    token = await pm.get_token(request)
    assert pm.has_permission(token, SecurityScopes(required_scopes)) == True
