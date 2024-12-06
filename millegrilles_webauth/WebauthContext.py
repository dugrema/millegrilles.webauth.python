from redis.asyncio.client import Redis as RedisClient

from typing import Optional

from millegrilles_web.Configuration import WebAppConfiguration
from millegrilles_web.Context import WebAppContext


class WebauthContext(WebAppContext):

    def __init__(self, configuration: WebAppConfiguration):
        super().__init__(configuration)
        self.__redis_client: Optional[RedisClient] = None

    @property
    def redis_client(self) -> RedisClient:
        return self.__redis_client

    @redis_client.setter
    def redis_client(self, value: RedisClient):
        self.__redis_client = value
