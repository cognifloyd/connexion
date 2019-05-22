import asyncio
import logging
import re
from urllib.parse import parse_qs

import aiohttp_jinja2
import jinja2
from aiohttp import web
from aiohttp.web_exceptions import HTTPNotFound, HTTPPermanentRedirect
from aiohttp.web_middlewares import normalize_path_middleware
from connexion.apis.abstract import AbstractAPI
from connexion.exceptions import OAuthProblem, OAuthScopeProblem
from connexion.handlers import AuthErrorHandler
from connexion.jsonifier import JSONEncoder, Jsonifier
from connexion.lifecycle import ConnexionRequest, ConnexionResponse
from connexion.security.aiohttp_security_handlers_factory import \
    AioHttpSecurityHandlerFactory
from connexion.utils import yamldumper

logger = logging.getLogger('connexion.apis.aiohttp_api')


@web.middleware
@asyncio.coroutine
def oauth_problem_middleware(request, handler):
    try:
        response = yield from handler(request)
    except (OAuthProblem, OAuthScopeProblem) as oauth_error:
        return web.Response(
            status=oauth_error.code,
            body=AioHttpApi.jsonifier.dumps(oauth_error.description).encode(),
            content_type='application/problem+json'
        )
    return response


class AioHttpApi(AbstractAPI):
    def __init__(self, *args, **kwargs):
        # NOTE we use HTTPPermanentRedirect (308) because
        # clients sometimes turn POST requests into GET requests
        # on 301, 302, or 303
        # see https://tools.ietf.org/html/rfc7538
        trailing_slash_redirect = normalize_path_middleware(
            append_slash=True,
            redirect_class=HTTPPermanentRedirect
        )
        self.subapp = web.Application(
            middlewares=[
                oauth_problem_middleware,
                trailing_slash_redirect
            ]
        )
        AbstractAPI.__init__(self, *args, **kwargs)

        aiohttp_jinja2.setup(
            self.subapp,
            loader=jinja2.FileSystemLoader(
                str(self.options.openapi_console_ui_from_dir)
            )
        )
        middlewares = self.options.as_dict().get('middlewares', [])
        self.subapp.middlewares.extend(middlewares)

    @staticmethod
    def make_security_handler_factory(pass_context_arg_name):
        """ Create default SecurityHandlerFactory to create all security check handlers """
        return AioHttpSecurityHandlerFactory(pass_context_arg_name)

    def _set_base_path(self, base_path):
        AbstractAPI._set_base_path(self, base_path)
        self._api_name = AioHttpApi.normalize_string(self.base_path)

    @staticmethod
    def normalize_string(string):
        return re.sub(r'[^a-zA-Z0-9]', '_', string.strip('/'))

    def add_openapi_json(self):
        """
        Adds openapi json to {base_path}/openapi.json
             (or {base_path}/swagger.json for swagger2)
        """
        logger.debug('Adding spec json: %s/%s', self.base_path,
                     self.options.openapi_spec_path)
        self.subapp.router.add_route(
            'GET',
            self.options.openapi_spec_path,
            self._get_openapi_json
        )

    def add_openapi_yaml(self):
        """
        Adds openapi json to {base_path}/openapi.json
             (or {base_path}/swagger.json for swagger2)
        """
        if not self.options.openapi_spec_path.endswith("json"):
            return

        openapi_spec_path_yaml = self.options.openapi_spec_path[:-len("json")] + "yaml"
        logger.debug('Adding spec yaml: %s/%s', self.base_path,
                     openapi_spec_path_yaml)
        self.subapp.router.add_route(
            'GET',
            openapi_spec_path_yaml,
            self._get_openapi_yaml
        )

    @asyncio.coroutine
    def _get_openapi_json(self, req):
        return web.Response(
            status=200,
            content_type='application/json',
            body=self.jsonifier.dumps(self.specification.raw)
        )

    @asyncio.coroutine
    def _get_openapi_yaml(self, req):
        return web.Response(
            status=200,
            content_type='text/yaml',
            body=yamldumper(self.specification.raw)
        )

    def add_swagger_ui(self):
        """
        Adds swagger ui to {base_path}/ui/
        """
        console_ui_path = self.options.openapi_console_ui_path.strip().rstrip('/')
        logger.debug('Adding swagger-ui: %s%s/',
                     self.base_path,
                     console_ui_path)

        for path in (
            console_ui_path + '/',
            console_ui_path + '/index.html',
        ):
            self.subapp.router.add_route(
                'GET',
                path,
                self._get_swagger_ui_home
            )

        # we have to add an explicit redirect instead of relying on the
        # normalize_path_middleware because we also serve static files
        # from this dir (below)

        @asyncio.coroutine
        def redirect(request):
            raise web.HTTPMovedPermanently(
                location=self.base_path + console_ui_path + '/'
            )

        self.subapp.router.add_route(
            'GET',
            console_ui_path,
            redirect
        )

        # this route will match and get a permission error when trying to
        # serve index.html, so we add the redirect above.
        self.subapp.router.add_static(
            console_ui_path,
            path=str(self.options.openapi_console_ui_from_dir),
            name='swagger_ui_static'
        )

    @aiohttp_jinja2.template('index.j2')
    @asyncio.coroutine
    def _get_swagger_ui_home(self, req):
        return {'openapi_spec_url': (self.base_path +
                                     self.options.openapi_spec_path)}

    def add_auth_on_not_found(self, security, security_definitions):
        """
        Adds a 404 error handler to authenticate and only expose the 404 status if the security validation pass.
        """
        logger.debug('Adding path not found authentication')
        not_found_error = AuthErrorHandler(
            self, _HttpNotFoundError(),
            security=security,
            security_definitions=security_definitions
        )
        endpoint_name = "{}_not_found".format(self._api_name)
        self.subapp.router.add_route(
            '*',
            '/{not_found_path}',
            not_found_error.function,
            name=endpoint_name
        )

    def _add_operation_internal(self, method, path, operation):
        method = method.upper()
        operation_id = operation.operation_id or path

        logger.debug('... Adding %s -> %s', method, operation_id,
                     extra=vars(operation))

        handler = operation.function
        endpoint_name = '{}_{}_{}'.format(
            self._api_name,
            AioHttpApi.normalize_string(path),
            method.lower()
        )
        self.subapp.router.add_route(
            method, path, handler, name=endpoint_name
        )

        if not path.endswith('/'):
            self.subapp.router.add_route(
                method, path + '/', handler, name=endpoint_name + '_'
            )

    @classmethod
    @asyncio.coroutine
    def get_request(cls, req):
        """Convert aiohttp request to connexion

        :param req: instance of aiohttp.web.Request
        :return: connexion request instance
        :rtype: ConnexionRequest
        """
        url = str(req.url)
        logger.debug('Getting data and status code',
                     extra={'has_body': req.has_body, 'url': url})

        query = parse_qs(req.rel_url.query_string)
        headers = req.headers
        body = None
        if req.body_exists:
            body = yield from req.read()

        return ConnexionRequest(url=url,
                                method=req.method.lower(),
                                path_params=dict(req.match_info),
                                query=query,
                                headers=headers,
                                body=body,
                                json_getter=lambda: cls.jsonifier.loads(body),
                                files={},
                                context=req)

    @classmethod
    @asyncio.coroutine
    def get_response(cls, response, mimetype=None, request=None):
        """Get response.
        This method is used in the lifecycle decorators

        :rtype: aiohttp.web.Response
        """
        while asyncio.iscoroutine(response):
            response = yield from response

        url = str(request.url) if request else ''

        response = cls._get_response(response, mimetype=mimetype, url=url)

        # TODO: I let this log here for full compatibility. But if we can modify it, it can go to _get_response()
        logger.debug('Got stream response with status code (%d)',
                     response.status, extra={'url': url})

        return response

    @classmethod
    def _is_framework_response(cls, response):
        """ Return True if `response` is a framework response class """
        return isinstance(response, web.StreamResponse)

    @classmethod
    def _framework_to_connexion_response(cls, response, mimetype):
        """ Cast framework response class to ConnexionResponse used for schema validation """
        return ConnexionResponse(
            status_code=response.status,
            mimetype=mimetype,
            content_type=response.content_type,
            headers=response.headers,
            body=response.body
        )

    @classmethod
    def _connexion_to_framework_response(cls, response, mimetype):
        """ Cast ConnexionResponse to framework response class """
        return cls._build_response(
            mimetype=response.mimetype or mimetype,
            status_code=response.status_code,
            content_type=response.content_type,
            headers=response.headers,
            data=response.body
        )

    @classmethod
    def _build_response(cls, data, mimetype, content_type=None, headers=None, status_code=None):
        if isinstance(data, web.StreamResponse):
            raise TypeError("Cannot return web.StreamResponse in tuple. Only raw data can be returned in tuple.")

        data, status_code = cls._prepare_body_and_status_code(data=data, mimetype=mimetype, status_code=status_code)

        if isinstance(data, str):
            text = data
            body = None
        else:
            text = None
            body = data

        content_type = content_type or mimetype
        return web.Response(body=body, text=text, headers=headers, status=status_code, content_type=content_type)

    @classmethod
    def _set_jsonifier(cls):
        cls.jsonifier = Jsonifier(cls=JSONEncoder)


class _HttpNotFoundError(HTTPNotFound):
    def __init__(self):
        self.name = 'Not Found'
        self.description = (
            'The requested URL was not found on the server. '
            'If you entered the URL manually please check your spelling and '
            'try again.'
        )
        self.code = type(self).status_code
        self.empty_body = True

        HTTPNotFound.__init__(self, reason=self.name)
