import base64
import functools
import logging
import os
import textwrap

import requests
from six.moves import http_cookies

from ..exceptions import ConnexionException, OAuthProblem, OAuthResponseProblem, OAuthScopeProblem
from ..utils import get_function_from_name

logger = logging.getLogger('connexion.api.security')

# use connection pool for OAuth tokeninfo
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
session = requests.Session()
session.mount('http://', adapter)
session.mount('https://', adapter)


class SecurityHandlerFactory:
    no_value = object()

    @staticmethod
    def _get_function(security_definition, security_definition_key, environ_key, default=None):
        """
        Return function by getting its name from security_definition or environment variable
        """
        func = security_definition.get(security_definition_key) or os.environ.get(environ_key)
        if func:
            return get_function_from_name(func)
        return default

    def get_tokeninfo_func(self, security_definition):
        """
        :type security_definition: dict
        :param get_token_info_remote_func Function executed to download token info from x-tokenInfoUrl
        :rtype: function

        >>> get_tokeninfo_url({'x-tokenInfoFunc': 'foo.bar'})
        '<function foo.bar>'
        """
        token_info_func = self._get_function(security_definition, "x-tokenInfoFunc", 'TOKENINFO_FUNC')
        if token_info_func:
            return token_info_func

        token_info_url = (security_definition.get('x-tokenInfoUrl') or
                          os.environ.get('TOKENINFO_URL'))
        if token_info_url:
            return functools.partial(cls.get_token_info_remote, token_info_url)

        return None

    @classmethod
    def get_scope_validate_func(cls, security_definition):
        """
        :type security_definition: dict
        :rtype: function

        >>> get_scope_validate_func({'x-scopeValidateFunc': 'foo.bar'})
        '<function foo.bar>'
        """
        return cls._get_function(security_definition, "x-scopeValidateFunc", 'SCOPEVALIDATE_FUNC', cls.validate_scope)

    @classmethod
    def get_basicinfo_func(cls, security_definition):
        """
        :type security_definition: dict
        :rtype: function

        >>> get_basicinfo_func({'x-basicInfoFunc': 'foo.bar'})
        '<function foo.bar>'
        """
        return cls._get_function(security_definition, "x-basicInfoFunc", 'BASICINFO_FUNC')

    @classmethod
    def get_apikeyinfo_func(cls, security_definition):
        """
        :type security_definition: dict
        :rtype: function

        >>> get_apikeyinfo_func({'x-apikeyInfoFunc': 'foo.bar'})
        '<function foo.bar>'
        """
        return cls._get_function(security_definition, "x-apikeyInfoFunc", 'APIKEYINFO_FUNC')

    @classmethod
    def get_bearerinfo_func(cls, security_definition):
        """
        :type security_definition: dict
        :rtype: function

        >>> get_bearerinfo_func({'x-bearerInfoFunc': 'foo.bar'})
        '<function foo.bar>'
        """
        return cls._get_function(security_definition, "x-bearerInfoFunc", 'BEARERINFO_FUNC')

    @staticmethod
    def security_passthrough(function):
        """
        :type function: types.FunctionType
        :rtype: types.FunctionType
        """
        return function

    @staticmethod
    def security_deny(function):
        """
        :type function: types.FunctionType
        :rtype: types.FunctionType
        """

        def deny(*args, **kwargs):
            raise ConnexionException("Error in security definitions")

        return deny

    @staticmethod
    def validate_scope(required_scopes, token_scopes):
        """
        :param required_scopes: Scopes required to access operation
        :param token_scopes: Scopes granted by authorization server
        :rtype: bool
        """
        required_scopes = set(required_scopes)
        if isinstance(token_scopes, list):
            token_scopes = set(token_scopes)
        else:
            token_scopes = set(token_scopes.split())
        logger.debug("... Scopes required: %s", required_scopes)
        logger.debug("... Token scopes: %s", token_scopes)
        if not required_scopes <= token_scopes:
            logger.info(textwrap.dedent("""
                        ... Token scopes (%s) do not match the scopes necessary to call endpoint (%s).
                         Aborting with 403.""").replace('\n', ''),
                        token_scopes, required_scopes)
            return False
        return True

    @staticmethod
    def get_auth_header_value(request):
        """
        Return Authorization type and value if any.
        If not Authorization, return (None, None)
        Raise OAuthProblem for invalid Authorization header
        """
        authorization = request.headers.get('Authorization')
        if not authorization:
            return None, None

        try:
            auth_type, value = authorization.split(None, 1)
        except ValueError:
            raise OAuthProblem(description='Invalid authorization header')
        return auth_type.lower(), value

    @classmethod
    def verify_oauth(cls, token_info_func, scope_validate_func):
        check_oauth_func = cls.check_oauth_func(token_info_func, scope_validate_func)

        def wrapper(request, required_scopes):
            auth_type, token = cls.get_auth_header_value(request)
            if auth_type != 'bearer':
                return cls.no_value

            return check_oauth_func(request, token, required_scopes)

        return wrapper

    @classmethod
    def verify_basic(cls, basic_info_func):
        check_basic_info_func = cls.check_basic_auth(basic_info_func)

        def wrapper(request, required_scopes):
            auth_type, user_pass = cls.get_auth_header_value(request)
            if auth_type != 'basic':
                return cls.no_value

            try:
                username, password = base64.b64decode(user_pass).decode('latin1').split(':', 1)
            except Exception:
                raise OAuthProblem(description='Invalid authorization header')

            return check_basic_info_func(request, username, password, required_scopes=required_scopes)

        return wrapper

    @staticmethod
    def get_cookie_value(cookies, name):
        '''
        Returns cookie value by its name. None if no such value.
        :param cookies: str: cookies raw data
        :param name: str: cookies key
        '''
        cookie_parser = http_cookies.SimpleCookie()
        cookie_parser.load(str(cookies))
        try:
            return cookie_parser[name].value
        except KeyError:
            return None

    @classmethod
    def verify_api_key(cls, api_key_info_func, loc, name):
        check_api_key_func = cls.check_api_key(api_key_info_func)

        def wrapper(request, required_scopes):
            if loc == 'query':
                api_key = request.query.get(name)
            elif loc == 'header':
                api_key = request.headers.get(name)
            elif loc == 'cookie':
                cookie_list = request.headers.get('Cookie')
                api_key = cls.get_cookie_value(cookie_list, name)
            else:
                return cls.no_value

            if api_key is None:
                return cls.no_value

            return check_api_key_func(request, api_key, required_scopes=required_scopes)

        return wrapper

    @classmethod
    def verify_bearer(cls, token_info_func):
        """
        :param check_bearer_func: types.FunctionType
        :rtype: types.FunctionType
        """
        check_bearer_func = cls.check_bearer_token(token_info_func)

        def wrapper(request, required_scopes):
            auth_type, token = cls.get_auth_header_value(request)
            if auth_type != 'bearer':
                return cls.no_value
            return check_bearer_func(request, token, required_scopes)

        return wrapper

    # ================================================================
    # Will be overwritten for AioHttp with commented asyncio parts
    # ================================================================

    """ Provide framework dependent security check wrappers """
    @classmethod
    def check_bearer_token(cls, token_info_func):
        # @asyncio.coroutine
        def wrapper(request, token, required_scopes):
            token_info = token_info_func(token)
            # while asyncio.iscoroutine(token_info):
            #     token_info = yield from token_info
            if token_info is cls.no_value:
                return cls.no_value
            if token_info is None:
                raise OAuthResponseProblem(description='Provided token is not valid')

            return token_info
        return wrapper

    @classmethod
    def check_basic_auth(cls, basic_info_func):
        # @asyncio.coroutine
        def wrapper(request, username, password, required_scopes):
            token_info = basic_info_func(username, password, required_scopes=required_scopes)
            # while asyncio.iscoroutine(token_info):
            #     token_info = yield from token_info
            if token_info is cls.no_value:
                return cls.no_value
            if token_info is None:
                raise OAuthResponseProblem(description='Provided authorization is not valid')

            return token_info
        return wrapper

    @classmethod
    def check_api_key(cls, api_key_info_func):
        # @asyncio.coroutine
        def wrapper(request, api_key, required_scopes):
            token_info = api_key_info_func(api_key, required_scopes=required_scopes)
            # while asyncio.iscoroutine(token_info):
            #     token_info = yield from token_info
            if token_info is cls.no_value:
                return cls.no_value
            if token_info is None:
                raise OAuthResponseProblem(description='Provided apikey is not valid')
            return token_info
        return wrapper

    @classmethod
    def check_oauth_func(cls, token_info_func, scope_validate_func):
        # @asyncio.coroutine
        def wrapper(request, token, required_scopes):

            token_info = token_info_func(token)
            # while asyncio.iscoroutine(token_info):
            #     token_info = yield from token_info
            if token_info is cls.no_value:
                return cls.no_value
            if token_info is None:
                raise OAuthResponseProblem(description='Provided token is not valid')

            # Fallback to 'scopes' for backward compatibility
            token_scopes = token_info.get('scope', token_info.get('scopes', ''))

            validation = scope_validate_func(required_scopes, token_scopes)
            # while asyncio.iscoroutine(validation):
            #     validation = yield from validation
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
        # @asyncio.coroutine
        @functools.wraps(function)
        def wrapper(request):
            token_info = None
            for func in auth_funcs:
                token_info = func(request, required_scopes)
                # while asyncio.iscoroutine(token_info):
                #     token_info = yield from token_info
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

    @staticmethod
    # @asyncio.coroutine
    def get_token_info_remote(token_info_url, token):
        """
        Retrieve oauth token_info remotely using HTTP
        :param token_info_url: Url to get information about the token
        :type token_info_url: str
        :param token: oauth token from authorization header
        :type token: str
        :rtype: dict
        """
        token_request = session.get(token_info_url, headers={'Authorization': 'Bearer {}'.format(token)}, timeout=5)
        if not token_request.ok:
            return None
        return token_request.json()
