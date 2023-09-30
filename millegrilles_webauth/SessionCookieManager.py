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

from typing import Union

from millegrilles_messages.messages import Constantes
from millegrilles_web.EtatWeb import EtatWeb
from millegrilles_webauth import Constantes as ConstantesWebAuth

SESSION_COOKIE_ENCRYPTION_KEY = b'01234567890123456789012345678901'


class SessionCookieManager:

    def __init__(self, etat: EtatWeb):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__etat = etat
        self.__session_cookie_encryption_Key = SESSION_COOKIE_ENCRYPTION_KEY

    def set_cookie(self, cookie: dict, response: Response):
        now = int(datetime.datetime.utcnow().timestamp())
        try:
            max_age = cookie['expiration'] - now

            cookie_bytes = json.dumps(cookie).encode('utf-8')

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
        except Exception as e:
            self.__logger.debug('Erreur dechiffrage cookie : %s' % str(e))
            return False

        # Verifier avec Redis

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
            return message_json

        return False

    async def desactiver_cookie(self, request: Request, response: Response):
        # Desactiver le cookie
        response.set_cookie(ConstantesWebAuth.COOKIE_MG_SESSION, '', max_age=0)

        try:
            message_json = self.extraire_info_cookie(request)
        except Exception as e:
            self.__logger.debug('Erreur dechiffrage cookie : %s' % str(e))
            return

        # Desactiver dans le back-end
        try:
            producer = await asyncio.wait_for(self.__etat.producer_wait(), timeout=0.3)
        except asyncio.TimeoutError:
            return

        await producer.executer_commande(message_json,
                                         domaine=Constantes.DOMAINE_CORE_MAITREDESCOMPTES,
                                         action='supprimerCookieSession',
                                         exchange=Constantes.SECURITE_PUBLIC,
                                         nowait=True)
