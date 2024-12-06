import asyncio
import logging

import redis.asyncio

from aiohttp.web_request import Request
from aiohttp.web_response import Response
from redis.asyncio.client import Redis as RedisClient

from typing import Optional

from millegrilles_messages.messages.MessagesModule import MessageWrapper
from millegrilles_web.WebAppManager import WebAppManager
from millegrilles_webauth.SessionCookieManager import SessionCookieManager
from millegrilles_webauth import Constantes as ConstantesWebAuth
from millegrilles_webauth.WebauthContext import WebauthContext


class WebauthManager(WebAppManager):

    def __init__(self, context: WebauthContext, session_cookie_manager: SessionCookieManager):
        super().__init__(context)
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        self.__session_cookie_manager = session_cookie_manager

    @property
    def app_name(self) -> str:
        return ConstantesWebAuth.APP_NAME

    @property
    def application_path(self):
        return f'/{ConstantesWebAuth.APP_NAME}'

    @property
    def context(self) -> WebauthContext:
        return super().context

    async def evict_user_message(self, message: MessageWrapper):
        user_id = message.parsed['user_id']
        await self.__session_cookie_manager.evict_user(user_id)

    async def evict_user(self, user_id: str):
        await self.__session_cookie_manager.evict_user(user_id)

    async def connect_redis(self, redis_database: Optional[int] = None) -> RedisClient:
        configuration_app = self.context.configuration
        redis_hostname = configuration_app.redis_hostname
        redis_port = configuration_app.redis_port
        redis_username = configuration_app.redis_username
        with open(configuration_app.redis_password_path, 'rt') as fp:
            redis_password = await asyncio.to_thread(fp.readline, 1024)
        key_path = configuration_app.key_path
        cert_path = configuration_app.cert_path
        ca_path = configuration_app.ca_path
        redis_database_val = redis_database or configuration_app.redis_session_db

        url_redis = f"rediss://{redis_hostname}:{redis_port}"

        self.__logger.info("Connecting to redis for web sessions : %s", url_redis)

        redis_session = await redis.asyncio.from_url(
            url_redis, db=redis_database_val, username=redis_username, password=redis_password,
            ssl_keyfile=key_path, ssl_certfile=cert_path, ssl_ca_certs=ca_path,
            ssl_cert_reqs="required", ssl_check_hostname=True,
        )

        return redis_session

    async def open_cookie_session(self, request: Request):
        return await self.__session_cookie_manager.ouvrir_session_cookie(request)

    async def set_cookie(self, nom_usager: str, cookie: dict, response: Response):
        return await self.__session_cookie_manager.set_cookie(nom_usager, cookie, response)

    async def deactivate_cookie(self, request: Request, response: Response):
        return await self.__session_cookie_manager.desactiver_cookie(request, response)
