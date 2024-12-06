import secrets
import asyncio
import base64
import datetime
import json
import nacl.secret
import nacl.utils
import logging

from aiohttp.web_request import Request
from aiohttp.web_response import Response

from typing import Union, Optional

from millegrilles_messages.messages import Constantes

from millegrilles_webauth import Constantes as ConstantesWebAuth
from millegrilles_webauth.WebauthContext import WebauthContext


class SessionCookieManager:

    def __init__(self, context: WebauthContext):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__context: WebauthContext = context
        self.__session_cookie_encryption_Key: Optional[bytes] = None

    async def setup(self):
        # Check if an existing cookie exists in redis.
        cookie_str = await self.__context.redis_client.get(ConstantesWebAuth.REDIS_COOKIE_SECRET)
        if cookie_str is None:
            # Generate and save cookie
            self.__session_cookie_encryption_Key = secrets.token_bytes(32)
            b64_cookie = base64.b64encode(self.__session_cookie_encryption_Key)
            await self.__context.redis_client.set(ConstantesWebAuth.REDIS_COOKIE_SECRET, b64_cookie)
        else:
            self.__session_cookie_encryption_Key = base64.b64decode(cookie_str)

    async def set_cookie(self, nom_usager: str, cookie: dict, response: Response):
        now = int(datetime.datetime.now().timestamp())
        try:
            max_age = cookie['expiration'] - now

            cookie_bytes = json.dumps(cookie).encode('utf-8')

            # Conserver le cookie dans redis
            try:
                # Ajouter le nom d'usager pour eviter appel a CoreMaitreDesComptes sur reactivation de la session
                cookie_redis = cookie.copy()
                cookie_redis['nomUsager'] = nom_usager
                await self.conserver_cookie_redis(cookie_redis)
            except Exception:
                self.__logger.exception("Erreur set cookie dans redis")

            box = nacl.secret.SecretBox(self.__session_cookie_encryption_Key)
            cookie_encrypted = box.encrypt(cookie_bytes)
            cookie_b64 = base64.b64encode(cookie_encrypted).decode('utf-8')

            # response.set_cookie('mgsession', cookie_b64, max_age=max_age,
            #   httponly=True, secure=True, samesite='Strict', domain='/')

            response.set_cookie(ConstantesWebAuth.COOKIE_MG_SESSION, cookie_b64,
                                max_age=max_age, httponly=True, secure=True)
        except KeyError:
            pass  # Pas de cookie

    def extraire_info_cookie(self, request: Request):
        cookie = request.cookies[ConstantesWebAuth.COOKIE_MG_SESSION]
        cookie_value = base64.b64decode(cookie.encode('utf-8'))
        message = nacl.secret.EncryptedMessage(cookie_value)

        box = nacl.secret.SecretBox(self.__session_cookie_encryption_Key)
        message_str = box.decrypt(message).decode('utf-8')

        return json.loads(message_str)

    async def ouvrir_session_cookie(self, request: Request) -> Union[dict, bool]:
        """
        Tenter d'ouvrir la session avec le cookie mgsession
        :param request:
        :return:
        """
        try:
            message_json = self.extraire_info_cookie(request)
            challenge = message_json['challenge']
        except Exception as e:
            self.__logger.debug('Erreur dechiffrage cookie : %s' % str(e))
            return False

        # Verifier avec Redis
        try:
            redis_key = f'mgsession.{challenge}'
            cookie_redis = await self.__context.redis_client.get(redis_key)
            cookie_json = json.loads(cookie_redis)

            if cookie_json.get('invalide') is True:
                return False  # Le cookie a ete desactive

            expiration = cookie_json['expiration']
            if expiration > datetime.datetime.now().timestamp():
                # Ok, cookie dans redis est valide
                return cookie_json
        except Exception:
            self.__logger.exception("Erreur chargement cookie dans redis")

        # Verifier avec CoreMaitreDesComptes
        try:
            producer = await asyncio.wait_for(self.__context.get_producer(), timeout=0.3)
        except asyncio.TimeoutError:
            return False  # Timeout

        reponse = await producer.request(
            message_json, domain=Constantes.DOMAINE_CORE_MAITREDESCOMPTES, action='getCookieUsager', exchange=Constantes.SECURITE_PUBLIC)

        if reponse.parsed.get('ok') is True:
            nom_usager = reponse.parsed['nomUsager']
            message_json['nomUsager'] = nom_usager

            # Remettre cookie dans redis
            try:
                await self.conserver_cookie_redis(message_json)
            except Exception:
                self.__logger.exception("Erreur set cookie dans redis")

            return message_json

        return False

    async def conserver_cookie_redis(self, cookie: dict):
        if cookie.get('nomUsager') is None:
            raise ValueError('nomUsager est requis')

        max_age = cookie['expiration'] - int(datetime.datetime.now().timestamp())
        challenge = cookie['challenge']
        redis_key = f'mgsession.{challenge}'
        cookie_redis_bytes = json.dumps(cookie).encode('utf-8')

        self.__logger.debug("Set cookie %s dans redis" % redis_key)
        await self.__context.redis_client.set(redis_key, cookie_redis_bytes, ex=max_age)

    async def desactiver_cookie(self, request: Request, response: Response):
        # Desactiver le cookie dans le navigateur
        response.set_cookie(ConstantesWebAuth.COOKIE_MG_SESSION, '', max_age=0)

        try:
            message_json = self.extraire_info_cookie(request)
            challenge = message_json["challenge"]
        except Exception as e:
            self.__logger.debug('Erreur dechiffrage cookie : %s' % str(e))
            return

        # Bloquer dans redis (on garde 5 minutes pour eviter multiples rappels au back-end par navigateur)
        try:
            redis_key = f'mgsession.{challenge}'
            info_bytes = json.dumps({'invalide': True}).encode('utf-8')
            await self.__context.redis_client.set(redis_key, info_bytes, ex=300)
        except Exception:
            self.__logger.exception("Erreur invalidation cookie dans redis")

        # Desactiver dans CoreMaitreDesComptes
        try:
            producer = await asyncio.wait_for(self.__context.get_producer(), timeout=0.3)
        except asyncio.TimeoutError:
            return

        await producer.command(
            message_json,
            domain=Constantes.DOMAINE_CORE_MAITREDESCOMPTES, action='supprimerCookieSession',
            exchange=Constantes.SECURITE_PUBLIC, nowait=True)

    async def evict_user(self, user_id):
        # Note : inefficient, reviser pour utiliser RediSearch avec index

        # Supprimer les cookies de longue duree
        for key in await self.__context.redis_client.keys('mgsession.*'):
            cookie_str = await self.__context.redis_client.get(key)
            cookie = json.loads(cookie_str)
            if cookie.get('user_id') == user_id:
                self.__logger.debug("Supprimer cookie %s" % key)
                await self.__context.redis_client.expire(key, 0)

        # Supprimer les sessions
        for key in await self.__context.redis_client.keys('auth.aiohttp_*'):
            session_str = await self.__context.redis_client.get(key)
            session = json.loads(session_str)
            try:
                if session['session']['userId'] == user_id:
                    self.__logger.debug("Supprimer cookie %s" % key)
                    await self.__context.redis_client.expire(key, 0)
            except KeyError:
                pass
