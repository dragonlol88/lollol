import typing as t
import functools
import types
import jwt

from datetime import timedelta
from fastapi import Request
from fastapi_login import LoginManager as _LoginManager
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

    def pop(self):
        try:
            manager = self._local.pop()
            if manager:
                del manager
        except KeyError:
            pass


@functools.singledispatch
def set_secret(secret, *args) -> Secret:
    raise TypeError("Unsupported object type %s" % secret)


@set_secret.register
def _(secret: str, *args):
    return Secret(secret)


@set_secret.register                                              # type: ignore
def _(secret: types.FunctionType, *args):
    return Secret(secret(*args))


class LoginManager(_LoginManager):

    def __init__(self,
                 secret: str,
                 token_url: str,
                 algorithm="HS256",
                 use_cookie=False,
                 use_header=True,
                 cookie_name: str = "access-token",
                 custom_exception: Exception = None,
                 default_expiry: timedelta = timedelta(minutes=15),
                 scopes: t.Dict[str, str] = None
                 ):
        super().__init__(
            secret, token_url, algorithm, use_cookie, use_header, cookie_name,
            custom_exception, default_expiry, scopes
        )

    def _get_payload_with_extrakey(self, token: str, extra_key: str):
        """
        Returns the decoded token payload
        Args:
            token: The token to decode
            extra_key: The extra key to be add at runtime.
        Returns:
            Payload of the token
        Raises:
            LoginManager.not_authenticated_exception: The token is invalid or None was returned by `_load_user`
        """
        try:
            payload = jwt.decode(
                token,
                str(self.secret) + extra_key,
                algorithms=[self.algorithm]
            )
            return payload

        # This includes all errors raised by pyjwt
        except jwt.PyJWTError:
            raise self.not_authenticated_exception


class PermissionManager:

    """

    """
    def __init__(self, manager: LoginManager, perm_key="scopes"):
        self._manager = manager
        self._pem_key = perm_key
        try:
            self._app_name = manager.app_name                      # type:ignore
        except AttributeError:
            pass

        self._register()

    @property
    def app_name(self):
        return self._app_name

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

    def has_permission(self,
                       token: str,
                       required_scopes: SecurityScopes,
                       extra_secret_key: t.Optional[str] = None
                       ) -> bool:
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
            try:
                if extra_secret_key is None:
                    return False
                payload = self._manager._get_payload_with_extrakey(token, extra_secret_key)
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
        secret_obj = set_secret(secret, *args)
        self._manager.secret = secret_obj

    def get_secret_key(self) -> Secret:
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