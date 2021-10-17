class AuthorizationError(Exception):

    """
    Permission error when user does not have permissions.
    """


class ScopeNotSpecified(Exception):
    """
    When scopes does not specified
    """
