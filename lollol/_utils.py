import types
import functools
import inspect
import typing as t

from fastapi import params
from fastapi import (
    FastAPI,
    APIRouter,
    Request,
    HTTPException,
    status
)
from fastapi.security import SecurityScopes
from fastapi.encoders import DictIntStrAny, SetIntStr
from fastapi.datastructures import Default
from fastapi.types import DecoratedCallable
from starlette.routing import BaseRoute
from starlette.responses import JSONResponse, Response

from ._authorize import lookup_permission_obj
from ._authorize import PermissionManager
from ._exceptions import ScopeNotSpecified

_REQUEST_VAR_NAME   = "request"
_X_REQUEST_VAR_NAME = "x_request"

_SCOPE_VAR_NAME = "scopes"
_EXTRA_SECRET_KEY = "x-extra-secret-key"

POSITIONAL_OR_KEYWORD = inspect._POSITIONAL_OR_KEYWORD            # type: ignore
POSITIONAL_ONLY = inspect._POSITIONAL_ONLY                         # type: ignore


def _get_parameter_if_have(
        target: t.Any,
        source: t.Any,
        compare_func: t.Callable,
        params: t.List[inspect.Parameter]
    ) -> t.Union[inspect.Parameter, None]:

    """
    Funtion to get parameter object if params have target object.

    :param target:
        A target object will be compared.
    :param source:
        A source object will compare the target.
    :param compare_func:
        A callable object will compare a source with a target.
    :param params:
        A list containing parameter objects.
    :return:
        Obj: Parameter
    """

    size = len(params)
    idx = 0
    while size - idx:
        param = params[idx]
        if compare_func(
                getattr(param, source), target
        ):
            params.remove(param)
            return param
        idx += 1

    return None


def _has_name(
        params: t.List[inspect.Parameter],
        name: str
    ) -> bool:

    size = len(params)
    idx = 0
    while size - idx:
        param = params[idx]
        if param.name == name:
            return True
        idx += 1
    return False


def _find_name(args: t.Tuple[str, ...], name: str):
    return any(name == arg for arg in args)


def _get_code_from_function(
                   func: types.FunctionType,
                   size: int,
                   *,
                   request: t.Optional[inspect.Parameter],
                   scope: t.Optional[inspect.Parameter]
                ) -> types.CodeType:

    if not inspect.isfunction(func):
        raise TypeError('{!r} does not function type'.format(func))

    _code = func.__code__

    # Parameter information.
    # after * sign parameter is keywordonly.
    # before / sign parameter is positiononly.
    # and the rest is positional.
    # co_argcount does not include keywordonly count.

    pos_count = _code.co_argcount
    keyword_only_count = _code.co_kwonlyargcount
    args_count = pos_count + keyword_only_count
    arg_names = _code.co_varnames

    diff_size = size - args_count
    if diff_size > 0:
        if not _find_name(arg_names, scope.name):                 # type: ignore
            arg_names += (scope.name, )                           # type: ignore

            if diff_size > 1:
                arg_names += (request.name,)                      # type: ignore
        else:
            arg_names += (request.name,)                          # type: ignore
        pos_count += diff_size
    return types.CodeType(
                          pos_count,
                          _code.co_posonlyargcount,
                          _code.co_kwonlyargcount,
                          _code.co_nlocals,
                          _code.co_stacksize,
                          _code.co_flags,
                          _code.co_code,
                          _code.co_consts,
                          _code.co_names,
                          arg_names,
                          _code.co_filename,
                          _code.co_name,
                          _code.co_firstlineno,
                          _code.co_lnotab
            )


def _authorize_required(
        endpoint, scopes: t.Optional[SecurityScopes] = None
) -> t.Callable:

    parameters = []
    is_duck_function = False
    annotations = endpoint.__annotations__

    # get signature of endpoint
    sig = inspect.signature(endpoint)
    sig_parameter = list(sig.parameters.values())

    # endpoint must be function.
    if not inspect.isfunction(endpoint):
        if inspect._signature_is_functionlike(endpoint):          # type: ignore
            is_duck_function = True
        else:
            # If it's not a pure Python function, and not a duck type
            # of pure function:
            raise TypeError('{!r} is not a Python function'.format(endpoint))

    # get scope parameter.
    scope: t.Optional[inspect.Parameter] = _get_parameter_if_have(
                                                        target=SecurityScopes,
                                                        source="default",
                                                        compare_func=isinstance,
                                                        params=sig_parameter
                                                )

    if not scope:
        if scopes is None:
            raise ScopeNotSpecified("scope must be present.")

        # get scope when authorization unit is router or app.
        scope = inspect.Parameter(
            "scopes", POSITIONAL_OR_KEYWORD, default=scopes, annotation=inspect._empty   # type: ignore
        )

    # scopes name must be _SCOPE_VAR_NAME
    if scope.name != _SCOPE_VAR_NAME:
        scope.name = _SCOPE_VAR_NAME

    request: t.Optional[inspect.Parameter] = _get_parameter_if_have(
                                                        target=Request,
                                                        source="annotation",
                                                        compare_func=issubclass,
                                                        params=sig_parameter)

    if request:
        # when request parameter is specified from user,
        # request_var_name have that request name.
        if request.name != _REQUEST_VAR_NAME:
            request_var_name = request.name
        else:
            request_var_name = _REQUEST_VAR_NAME

    else:
        # if request parameter have same _REQUEST_VAR_NAME and different type,
        # request_var_name have secondary name for request object.
        if _has_name(sig_parameter, _REQUEST_VAR_NAME):
            request_var_name = _X_REQUEST_VAR_NAME
        else:
            request_var_name = _REQUEST_VAR_NAME
        request = inspect.Parameter(
            name=request_var_name,
            annotation=Request,
            kind=POSITIONAL_OR_KEYWORD
        )
    # sort parameter according to python parameter ordering rules.
    # ( position only > position > keyword > keyword only)

    if sig_parameter:
        for param in sig_parameter:
            if param.kind == POSITIONAL_ONLY:
                # first, add all the position only parameters.
                parameters.append(param)
                continue

            exist_request = list(
                map(lambda x: x == request, parameters)
            )

            if not any(exist_request):
                parameters.append(request)

            parameters.append(param)
    else:
        parameters.append(request)

    parameters.append(scope)
    new_sig = inspect.Signature(
                      parameters,
                      return_annotation=annotations.get('return', inspect._empty),   # type: ignore
                      __validate_parameters__=is_duck_function                       # type: ignore
    )
    endpoint.__signature__ = new_sig
    annotations[request_var_name] = Request

    modified = types.FunctionType(
        _get_code_from_function(
            endpoint, len(parameters), request=request, scope=scope
        ),
        endpoint.__globals__
    )
    _code = endpoint.__code__
    org_argnames = _code.co_varnames
    endpoint.__code__ = modified.__code__

    @functools.wraps(endpoint)
    async def decorator(*args, **kwargs):
        request_obj: Request = kwargs.pop(request_var_name, None)
        extra_secret_key = None

        if not scopes and _find_name(org_argnames, request_var_name):
            kwargs[request_var_name] = request_obj
        elif scopes:
            kwargs[request_var_name] = request_obj
        required_scope = kwargs.get(_SCOPE_VAR_NAME, None)

        manager: PermissionManager = lookup_permission_obj()
        access_token = await manager.get_token(request_obj)
        headers = request_obj.headers

        # extra secret key
        if _EXTRA_SECRET_KEY in headers:
            extra_secret_key = headers.get(_EXTRA_SECRET_KEY)
        have_permission = manager.has_permission(
                                token=access_token,
                                required_scopes=required_scope,
                                extra_secret_key=extra_secret_key
                            )
        if not have_permission:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="does not have authorization.")
        response = await endpoint(*args, **kwargs)
        return response
    return decorator


authorize_required = functools.partial(
                        _authorize_required, scopes=None
                    )


def _get_router(obj):
    if isinstance(obj, APIRouter):
        return obj
    elif isinstance(obj, FastAPI):
        router = getattr(obj, "router", None)
        if router is None:
            raise AttributeError(
                "Does not exist router attribute in %s" % str(type(obj))
            )
        return router


def authorize_router(router: APIRouter, scopes: SecurityScopes) -> APIRouter:

    def api_route(
            path: str,
            *,
            response_model: t.Optional[t.Type[t.Any]] = None,
            status_code: t.Optional[int] = None,
            tags: t.Optional[t.List[str]] = None,
            dependencies: t.Optional[t.Sequence[params.Depends]] = None,
            summary: t.Optional[str] = None,
            description: t.Optional[str] = None,
            response_description: str = "Successful Response",
            responses: t.Optional[t.Dict[t.Union[int, str], t.Dict[str, t.Any]]] = None,
            deprecated: t.Optional[bool] = None,
            methods: t.Optional[t.List[str]] = None,
            operation_id: t.Optional[str] = None,
            response_model_include: t.Optional[
                t.Union[SetIntStr, DictIntStrAny]] = None,
            response_model_exclude: t.Optional[
                t.Union[SetIntStr, DictIntStrAny]] = None,
            response_model_by_alias: bool = True,
            response_model_exclude_unset: bool = False,
            response_model_exclude_defaults: bool = False,
            response_model_exclude_none: bool = False,
            include_in_schema: bool = True,
            response_class: t.Type[Response] = Default(JSONResponse),
            name: t.Optional[str] = None,
            callbacks: t.Optional[t.List[BaseRoute]] = None,
            openapi_extra: t.Optional[t.Dict[str, t.Any]] = None,
    ) -> t.Callable:

        def decorator(func: DecoratedCallable) -> t.Callable:

            endpoint = _authorize_required(func, scopes)
            router.add_api_route(
                path,
                endpoint,
                response_model=response_model,
                status_code=status_code,
                tags=tags,
                dependencies=dependencies,
                summary=summary,
                description=description,
                response_description=response_description,
                responses=responses,
                deprecated=deprecated,
                methods=methods,
                operation_id=operation_id,
                response_model_include=response_model_include,
                response_model_exclude=response_model_exclude,
                response_model_by_alias=response_model_by_alias,
                response_model_exclude_unset=response_model_exclude_unset,
                response_model_exclude_defaults=response_model_exclude_defaults,
                response_model_exclude_none=response_model_exclude_none,
                include_in_schema=include_in_schema,
                response_class=response_class,
                name=name,
                callbacks=callbacks,
                openapi_extra=openapi_extra,
            )
            return endpoint

        return decorator

    router.api_route = api_route                                  # type: ignore

    return router


def authorize_app(app: FastAPI, scopes: SecurityScopes) -> FastAPI:
    authorize_router(_get_router(app), scopes)
    return app
