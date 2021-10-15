import pytest
from src.lollol import PermissionManager, LoginManager
from src.lollol import lookup_permission_obj


secret_key = "hello secret"
manager = LoginManager("test_secret", '/auth', use_header=True)
manager.app_name = "test"


def secret():
    return secret_key


def _release_app_name():
    del manager.app_name


def test_permission():
    pm = PermissionManager(manager)
    l_pm = lookup_permission_obj()
    assert pm == l_pm


def test_secret_key_from_callable():
    pm = PermissionManager(manager)
    pm.set_secret_key(secret)

    assert str(pm.get_secret_key()) == "hello secret"


def test_secret_key_from_str():
    pm = PermissionManager(manager)
    pm.set_secret_key(secret_key)

    assert str(pm.get_secret_key()) == "hello secret"


def test_after_releasing_app_name():
    _release_app_name()
    with pytest.raises(AttributeError):
        PermissionManager(manager)
