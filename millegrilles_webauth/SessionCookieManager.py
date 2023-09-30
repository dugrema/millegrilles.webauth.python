import aiohttp
import asyncio
import datetime
import base64
import datetime
import json
import nacl.secret
import nacl.utils
import logging

from aiohttp.web_request import Request
from aiohttp.web_response import Response
from redis.asyncio.client import Redis

from typing import Union

from millegrilles_messages.messages import Constantes
from millegrilles_web.EtatWeb import EtatWeb
from millegrilles_webauth import Constantes as ConstantesWebAuth

SESSION_COOKIE_ENCRYPTION_KEY = b'01234567890123456789012345678901'


class SessionCookieManager:

    def __init__(self, redis_client: Redis, etat: EtatWeb):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__redis_client = redis_client
        self.__etat = etat
        self.__session_cookie_encryption_Key = SESSION_COOKIE_ENCRYPTION_KEY

    async def set_cookie(self, nom_usager: str, cookie: dict, response: Response):
        now = int(datetime.datetime.utcnow().timestamp())
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
            cookie_redis = await self.__redis_client.get(redis_key)
            cookie_json = json.loads(cookie_redis)

            if cookie_json.get('invalide') is True:
                return False  # Le cookie a ete desactive

            expiration = cookie_json['expiration']
            if expiration > datetime.datetime.utcnow().timestamp():
                # Ok, cookie dans redis est valide
                return cookie_json
        except Exception:
            self.__logger.exception("Erreur chargement cookie dans redis")

        # Verifier avec CoreMaitreDesComptes
        try:
            producer = await asyncio.wait_for(self.__etat.producer_wait(), timeout=0.3)
        except asyncio.TimeoutError:
            return False  # Timeout

        reponse = await producer.executer_requete(message_json,
                                                  domaine=Constantes.DOMAINE_CORE_MAITREDESCOMPTES,
                                                  action='getCookieUsager',
                                                  exchange=Constantes.SECURITE_PUBLIC)

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

        max_age = cookie['expiration'] - int(datetime.datetime.utcnow().timestamp())
        challenge = cookie['challenge']
        redis_key = f'mgsession.{challenge}'
        cookie_redis_bytes = json.dumps(cookie).encode('utf-8')

        self.__logger.debug("Set cookie %s dans redis" % redis_key)
        await self.__redis_client.set(redis_key, cookie_redis_bytes, ex=max_age)

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
            await self.__redis_client.set(redis_key, info_bytes, ex=300)
        except Exception:
            self.__logger.exception("Erreur invalidation cookie dans redis")

        # Desactiver dans CoreMaitreDesComptes
        try:
            producer = await asyncio.wait_for(self.__etat.producer_wait(), timeout=0.3)
        except asyncio.TimeoutError:
            return

        await producer.executer_commande(message_json,
                                         domaine=Constantes.DOMAINE_CORE_MAITREDESCOMPTES,
                                         action='supprimerCookieSession',
                                         exchange=Constantes.SECURITE_PUBLIC,
                                         nowait=True)
