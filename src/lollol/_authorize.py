import typing as t
import functools
import types

from fastapi import Request
from fastapi_login import LoginManager
from fastapi.security import SecurityScopes
from starlette.datastructures import Secret


StrInt = t.Union[str, int]


class _PermissionLocal:

    def __init__(self):
        self._local = []

    def register(self, manager):
        self._local.append(manager)

    def get(self):
        try:
            manager = self._local[-1]
        except IndexError:
            return

        return manager


@functools.singledispatch
def set_secret(secret, *args):
    raise TypeError("Unsupported object type %s" % secret)


@set_secret.register
def _(secret: str, *args):
    return Secret(secret)


@set_secret.register
def _(secret: types.FunctionType, *args):
    return Secret(secret(*args))


class PermissionManager:

    """

    """
    def __init__(self, manager: LoginManager, perm_key="scopes"):
        self._manager = manager
        self._pem_key = perm_key
        try:
            self._app_name = manager.app_name
        except AttributeError:
            raise AttributeError("set app_name attribute")

        self._register()

    def _register(self) -> None:
        """
        Method to register permission manager to pro
        :return:

        """
        _pemission_local.register(self)

    async def get_token(self, request: Request):
        """
        Method to get token from request headers.
        Header example:
            Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        :param request:
            FastApi request object contain a header.
            type: object
        :return:
            A access token
            type: str
        """

        token = await self._manager._get_token(request)
        return token

    def has_permission(self, token: str, required_scopes: SecurityScopes) -> bool:
        """
        Method to check permissions to compare the required scopes and scopes
        that granted to users.
        :param token:
            A access token which identifies the users.
            type: str
        :param required_scopes:
            A scopes specified by developer according to policies.
            type: object
        :return:
            True if user have permission that resource elsewise False.
        """

        try:
            payload = self._manager._get_payload(token)
        except type(self._manager.not_authenticated_exception):
            # We got an error while decoding the token
            return False

        scopes = payload.get(self._pem_key, [])
        # Check if all scopes are present

        if all(scope not in scopes for scope in required_scopes.scopes):
            return False

        return True

    def set_secret_key(self, secret: t.Union[str, t.Callable], *args) -> None:
        """
        Method to set a secret key from str or callable object.
        :param secret:
            A callable object which creates secret key or static string secret key
            type: str or callable object
        :return:
            None
        """
        secret = set_secret(secret, *args)
        self._manager.secret = secret

    def get_secret_key(self) -> str:
        """
        Method to get secret key for decoding json web token.
        :return:
            A secret key.
            type: str
        """
        return self._manager.secret


def lookup_permission_obj():

    obj = _pemission_local.get()

    if obj is None:
        raise KeyError("permission object does not exist. \
                            first initialize PermissionManager."
            )
    return obj


_pemission_local = _PermissionLocal()