import asyncio
import logging

import aiohttp

from ..exceptions import OAuthResponseProblem
from .async_security_handler_factory import AbstractAsyncSecurityHandlerFactory

logger = logging.getLogger('connexion.api.security')


class AioHttpSecurityHandlerFactory(AbstractAsyncSecurityHandlerFactory):
    def __init__(self, pass_context_arg_name):
        super(AioHttpSecurityHandlerFactory, self).__init__(pass_context_arg_name=pass_context_arg_name)
        self.client_session = None

    def get_token_info_remote(self, token_info_url):
        """
        Return a function which will call `token_info_url` to retrieve token info.

        Returned function must accept oauth token in parameter.
        It must return a token_info dict in case of success, None otherwise.

        This is the only method where it makes sense to raise OAuthResponseProblem

        :param token_info_url: Url to get information about the token
        :type token_info_url: str
        :rtype: types.FunctionType
        """
        async def wrapper(token):
            if not self.client_session:
                # Must be created in a coroutine
                self.client_session = aiohttp.ClientSession()
            headers = {'Authorization': 'Bearer {}'.format(token)}
            token_response = await self.client_session.get(
                token_info_url, headers=headers, timeout=self.remote_token_timeout
            )
            if token_response.status != 200:
                raise OAuthResponseProblem(
                    description="Provided token is not valid",
                    token_response=token_response
                )
            return token_response.json()
        return wrapper
