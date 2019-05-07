import asyncio
import functools
import logging

from ..exceptions import OAuthProblem, OAuthResponseProblem, OAuthScopeProblem
from .security_handler_factory import SecurityHandlerFactory

logger = logging.getLogger('connexion.api.security')


class AsyncSecurityHandlerFactory(SecurityHandlerFactory):
    @classmethod
    def check_bearer_token(cls, token_info_func):
        @asyncio.coroutine
        def wrapper(request, token, required_scopes):
            token_info = token_info_func(token)
            while asyncio.iscoroutine(token_info):
                token_info = yield from token_info
            if token_info is cls.no_value:
                return cls.no_value
            if token_info is None:
                raise OAuthResponseProblem(description='Provided token is not valid')

            return token_info
        return wrapper

    @classmethod
    def check_basic_auth(cls, basic_info_func):
        @asyncio.coroutine
        def wrapper(request, username, password, required_scopes):
            token_info = basic_info_func(username, password, required_scopes=required_scopes)
            while asyncio.iscoroutine(token_info):
                token_info = yield from token_info
            if token_info is cls.no_value:
                return cls.no_value
            if token_info is None:
                raise OAuthResponseProblem(description='Provided authorization is not valid')

            return token_info
        return wrapper

    @classmethod
    def check_api_key(cls, api_key_info_func):
        @asyncio.coroutine
        def wrapper(request, api_key, required_scopes):
            token_info = api_key_info_func(api_key, required_scopes=required_scopes)
            while asyncio.iscoroutine(token_info):
                token_info = yield from token_info
            if token_info is cls.no_value:
                return cls.no_value
            if token_info is None:
                raise OAuthResponseProblem(description='Provided apikey is not valid')
            return token_info
        return wrapper

    @classmethod
    def check_oauth_func(cls, token_info_func, scope_validate_func):
        @asyncio.coroutine
        def wrapper(request, token, required_scopes):

            token_info = token_info_func(token)
            while asyncio.iscoroutine(token_info):
                token_info = yield from token_info
            if token_info is cls.no_value:
                return cls.no_value
            if token_info is None:
                raise OAuthResponseProblem(description='Provided token is not valid')

            # Fallback to 'scopes' for backward compatibility
            token_scopes = token_info.get('scope', token_info.get('scopes', ''))

            validation = scope_validate_func(required_scopes, token_scopes)
            while asyncio.iscoroutine(validation):
                validation = yield from validation
            if not validation:
                raise OAuthScopeProblem(
                    description='Provided token doesn\'t have the required scope',
                    required_scopes=required_scopes,
                    token_scopes=token_scopes
                    )

            return token_info
        return wrapper

    @classmethod
    def verify_security(cls, auth_funcs, required_scopes, function):
        @asyncio.coroutine
        @functools.wraps(function)
        def wrapper(request):
            token_info = None
            for func in auth_funcs:
                token_info = func(request, required_scopes)
                while asyncio.iscoroutine(token_info):
                    token_info = yield from token_info
                if token_info is not cls.no_value:
                    break

            if token_info is cls.no_value:
                logger.info("... No auth provided. Aborting with 401.")
                raise OAuthProblem(description='No authorization token provided')

            # Fallback to 'uid' for backward compatibility
            request.context['user'] = token_info.get('sub', token_info.get('uid'))
            request.context['token_info'] = token_info
            return function(request)

        return wrapper
