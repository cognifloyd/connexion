import logging

import flask
import six
import werkzeug.exceptions
from connexion.apis import flask_utils
from connexion.apis.abstract import AbstractAPI
from connexion.handlers import AuthErrorHandler
from connexion.jsonifier import Jsonifier
from connexion.lifecycle import ConnexionRequest, ConnexionResponse
from connexion.utils import is_json_mimetype, yamldumper
from werkzeug.local import LocalProxy

logger = logging.getLogger('connexion.apis.flask_api')


class FlaskApi(AbstractAPI):

    def _set_base_path(self, base_path):
        super(FlaskApi, self)._set_base_path(base_path)
        self._set_blueprint()

    def _set_blueprint(self):
        logger.debug('Creating API blueprint: %s', self.base_path)
        endpoint = flask_utils.flaskify_endpoint(self.base_path)
        self.blueprint = flask.Blueprint(endpoint, __name__, url_prefix=self.base_path,
                                         template_folder=str(self.options.openapi_console_ui_from_dir))

    def add_openapi_json(self):
        """
        Adds spec json to {base_path}/swagger.json
        or {base_path}/openapi.json (for oas3)
        """
        logger.debug('Adding spec json: %s/%s', self.base_path,
                     self.options.openapi_spec_path)
        endpoint_name = "{name}_openapi_json".format(name=self.blueprint.name)
        self.blueprint.add_url_rule(self.options.openapi_spec_path,
                                    endpoint_name,
                                    lambda: flask.jsonify(self.specification.raw))

    def add_openapi_yaml(self):
        """
        Adds spec yaml to {base_path}/swagger.yaml
        or {base_path}/openapi.yaml (for oas3)
        """
        if not self.options.openapi_spec_path.endswith("json"):
            return

        openapi_spec_path_yaml = self.options.openapi_spec_path[:-len("json")] + "yaml"
        logger.debug('Adding spec yaml: %s/%s', self.base_path,
                     openapi_spec_path_yaml)
        endpoint_name = "{name}_openapi_yaml".format(name=self.blueprint.name)
        self.blueprint.add_url_rule(
            openapi_spec_path_yaml,
            endpoint_name,
            lambda: FlaskApi._build_response(
                status_code=200,
                mimetype="text/yaml",
                data=yamldumper(self.specification.raw)
            )
        )

    def add_swagger_ui(self):
        """
        Adds swagger ui to {base_path}/ui/
        """
        console_ui_path = self.options.openapi_console_ui_path.strip('/')
        logger.debug('Adding swagger-ui: %s/%s/',
                     self.base_path,
                     console_ui_path)

        if self.options.openapi_console_ui_config is not None:
            config_endpoint_name = "{name}_swagger_ui_config".format(name=self.blueprint.name)
            config_file_url = '/{console_ui_path}/swagger-ui-config.json'.format(
                console_ui_path=console_ui_path)

            self.blueprint.add_url_rule(config_file_url,
                                        config_endpoint_name,
                                        lambda: flask.jsonify(self.options.openapi_console_ui_config))

        static_endpoint_name = "{name}_swagger_ui_static".format(name=self.blueprint.name)
        static_files_url = '/{console_ui_path}/<path:filename>'.format(
            console_ui_path=console_ui_path)

        self.blueprint.add_url_rule(static_files_url,
                                    static_endpoint_name,
                                    self._handlers.console_ui_static_files)

        index_endpoint_name = "{name}_swagger_ui_index".format(name=self.blueprint.name)
        console_ui_url = '/{console_ui_path}/'.format(
            console_ui_path=console_ui_path)

        self.blueprint.add_url_rule(console_ui_url,
                                    index_endpoint_name,
                                    self._handlers.console_ui_home)

    def add_auth_on_not_found(self, security, security_definitions):
        """
        Adds a 404 error handler to authenticate and only expose the 404 status if the security validation pass.
        """
        logger.debug('Adding path not found authentication')
        not_found_error = AuthErrorHandler(self, werkzeug.exceptions.NotFound(), security=security,
                                           security_definitions=security_definitions)
        endpoint_name = "{name}_not_found".format(name=self.blueprint.name)
        self.blueprint.add_url_rule('/<path:invalid_path>', endpoint_name, not_found_error.function)

    def _add_operation_internal(self, method, path, operation):
        operation_id = operation.operation_id
        logger.debug('... Adding %s -> %s', method.upper(), operation_id,
                     extra=vars(operation))

        flask_path = flask_utils.flaskify_path(path, operation.get_path_parameter_types())
        endpoint_name = flask_utils.flaskify_endpoint(operation.operation_id,
                                                      operation.randomize_endpoint)
        function = operation.function
        self.blueprint.add_url_rule(flask_path, endpoint_name, function, methods=[method])

    @property
    def _handlers(self):
        # type: () -> InternalHandlers
        if not hasattr(self, '_internal_handlers'):
            self._internal_handlers = InternalHandlers(self.base_path, self.options)
        return self._internal_handlers

    @classmethod
    def get_response(cls, response, mimetype=None, request=None):
        """Gets ConnexionResponse instance for the operation handler
        result. Status Code and Headers for response.  If only body
        data is returned by the endpoint function, then the status
        code will be set to 200 and no headers will be added.

        If the returned object is a flask.Response then it will just
        pass the information needed to recreate it.

        :type response: flask.Response | (flask.Response,) | (flask.Response, int) | (flask.Response, dict) | (flask.Response, int, dict)
        :rtype: ConnexionResponse
        """
        return cls._get_response(response, mimetype=mimetype, extra_context={"url": flask.request.url})

    @classmethod
    def _is_framework_response(cls, response):
        """ Return True if provided response is a framework type """
        return flask_utils.is_flask_response(response)

    @classmethod
    def _framework_to_connexion_response(cls, response, mimetype):
        """ Cast framework response class to ConnexionResponse used for schema validation """
        return ConnexionResponse(
            status_code=response.status_code,
            mimetype=response.mimetype,
            content_type=response.content_type,
            headers=response.headers,
            body=response.get_data(),
        )

    @classmethod
    def _connexion_to_framework_response(cls, response, mimetype, extra_context=None):
        """ Cast ConnexionResponse to framework response class """
        flask_response = cls._build_response(
            mimetype=response.mimetype or mimetype,
            content_type=response.content_type,
            headers=response.headers,
            status_code=response.status_code,
            data=response.body,
            extra_context=extra_context,
            )

        return flask_response

    @classmethod
    def _build_response(cls, mimetype, content_type=None, headers=None, status_code=None, data=None, extra_context=None):
        if cls._is_framework_response(data):
            return flask.current_app.make_response((data, status_code, headers))

        data, status_code = cls._prepare_body_and_status_code(data=data, mimetype=mimetype, status_code=status_code, extra_context=extra_context)

        kwargs = {
            'mimetype': mimetype,
            'content_type': content_type,
            'headers': headers,
            'response': data,
            'status': status_code
        }
        kwargs = {k: v for k, v in six.iteritems(kwargs) if v is not None}
        return flask.current_app.response_class(**kwargs)  # type: flask.Response

    @classmethod
    def _jsonify_data(cls, data, mimetype):
        # TODO: to discuss: Using jsonifier for all type of data, even when mimetype is not json is strange. Why ?
        if (isinstance(mimetype, str) and is_json_mimetype(mimetype)) \
                or not (isinstance(data, bytes) or isinstance(data, str)):
            return cls.jsonifier.dumps(data)

        return data

    @classmethod
    def get_request(cls, *args, **params):
        # type: (*Any, **Any) -> ConnexionRequest
        """Gets ConnexionRequest instance for the operation handler
        result. Status Code and Headers for response.  If only body
        data is returned by the endpoint function, then the status
        code will be set to 200 and no headers will be added.

        If the returned object is a flask.Response then it will just
        pass the information needed to recreate it.

        :rtype: ConnexionRequest
        """
        context_dict = {}
        setattr(flask._request_ctx_stack.top, 'connexion_context', context_dict)
        flask_request = flask.request
        request = ConnexionRequest(
            flask_request.url,
            flask_request.method,
            headers=flask_request.headers,
            form=flask_request.form,
            query=flask_request.args,
            body=flask_request.get_data(),
            json_getter=lambda: flask_request.get_json(silent=True),
            files=flask_request.files,
            path_params=params,
            context=context_dict
        )
        logger.debug('Getting data and status code',
                     extra={
                         'data': request.body,
                         'data_type': type(request.body),
                         'url': request.url
                     })
        return request

    @classmethod
    def _set_jsonifier(cls):
        """
        Use Flask specific JSON loader
        """
        cls.jsonifier = Jsonifier(flask.json, indent=2)


def _get_context():
    return getattr(flask._request_ctx_stack.top, 'connexion_context')


context = LocalProxy(_get_context)


class InternalHandlers(object):
    """
    Flask handlers for internally registered endpoints.
    """

    def __init__(self, base_path, options):
        self.base_path = base_path
        self.options = options

    def console_ui_home(self):
        """
        Home page of the OpenAPI Console UI.

        :return:
        """
        template_variables = {
            'openapi_spec_url': (self.base_path + self.options.openapi_spec_path)
        }
        if self.options.openapi_console_ui_config is not None:
            template_variables['configUrl'] = 'swagger-ui-config.json'
        return flask.render_template('index.j2', **template_variables)

    def console_ui_static_files(self, filename):
        """
        Servers the static files for the OpenAPI Console UI.

        :param filename: Requested file contents.
        :return:
        """
        # convert PosixPath to str
        static_dir = str(self.options.openapi_console_ui_from_dir)
        return flask.send_from_directory(static_dir, filename)
