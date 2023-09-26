import asyncio
import base64
import datetime
import nacl.secret
import nacl.utils

from aiohttp import web
from aiohttp.web_request import Request
from aiohttp_session import get_session

import logging

from millegrilles_messages.messages import Constantes
from millegrilles_web.WebServer import WebServer
from millegrilles_web import Constantes as ConstantesWeb
from millegrilles_webauth import Constantes as ConstantesWebAuth


SESSION_COOKIE_ENCRYPTION_KEY = b'01234567890123456789012345678901'


class WebServerAuth(WebServer):

    def __init__(self, etat, commandes):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        super().__init__(ConstantesWebAuth.WEBAPP_PATH, etat, commandes)

        self.__semaphore_authentifier = asyncio.BoundedSemaphore(value=2)
        self.__semaphore_verifier_usager = asyncio.BoundedSemaphore(value=5)
        self.__semaphore_verifier_tls = asyncio.BoundedSemaphore(value=10)
        self.__session_encryption_key = SESSION_COOKIE_ENCRYPTION_KEY

    def get_nom_app(self) -> str:
        return ConstantesWebAuth.APP_NAME

    async def setup_socketio(self):
        # Ne pas initialiser socket.io
        pass

    async def _preparer_routes(self):
        self.__logger.info("Preparer routes %s sous /%s" % (self.__class__.__name__, self.get_nom_app()))
        await super()._preparer_routes()

        # Routes usager
        self.app.router.add_post(f'/auth/get_usager', self.get_usager),
        self.app.router.add_post(f'/auth/authentifier_usager', self.authentifier_usager),
        self.app.router.add_get(f'/auth/deconnecter_usager', self.deconnecter_usager),
        self.app.router.add_get(f'/auth/verifier_usager', self.verifier_usager),
        self.app.router.add_get(f'/auth/verifier_usager_noauth', self.verifier_usager_noauth),

        # Routes client TLS (certificat x509)
        self.app.router.add_get(f'/auth/verifier_client_tls', self.verifier_client_tls),

    async def get_usager(self, request: Request):
        async with self.__semaphore_authentifier:

            try:
                producer = await asyncio.wait_for(self.etat.producer_wait(), timeout=0.3)
            except TimeoutError:
                self.__logger.error("MQ timeout (producer_wait)")
                return web.HTTPServerError(text='MQ timeout (1)')

            message = await request.json()

            try:
                nom_usager = message['nomUsager']
                hostname = message['hostname']
            except KeyError:
                return web.HTTPBadRequest(text='Params nomUsager ou hostname manquants')
            fingerprint_public_nouveau = message.get('fingerprintPublicNouveau')
            generer_challenge = message.get('genererChallenge') or False

            requete_usager = {'nomUsager': nom_usager, 'hostUrl': hostname}

            coros = list()

            coros.append(producer.executer_requete(
                requete_usager,
                domaine=Constantes.DOMAINE_CORE_MAITREDESCOMPTES, action='chargerUsager',
                exchange=Constantes.SECURITE_PUBLIC
            ))

            if fingerprint_public_nouveau:
                requete_fingperint = {'fingerprint_pk': fingerprint_public_nouveau}
                coros.append(producer.executer_requete(
                    requete_fingperint,
                    domaine=Constantes.DOMAINE_CORE_PKI, action='certificatParPk',
                    exchange=Constantes.SECURITE_PUBLIC
                ))

            try:
                resultat = await asyncio.gather(*coros)
            except asyncio.TimeoutError:
                self.__logger.error("MQ timeout (coros)")
                return web.HTTPServerError(text='MQ timeout (2)')
            except Exception as e:
                self.__logger.exception("get_usager Erreur handling coros")
                return web.HTTPServerError(text='Server error')

            resultat_compte = resultat[0].parsed
            if resultat_compte['ok'] is not True:
                self.__logger.error("Erreur reponse compte usager (ok!=True) : %s" % resultat_compte)
                return web.HTTPServerError(text='Server error')

            del resultat_compte['__original']
            compte_usager = resultat_compte['compte']
            # reponse_originale = compte_usager['__original']

            reponse_dict = dict()

            # Conserver information dans la session au besoin
            session = await get_session(request)
            session.changed()
            try:
                session[ConstantesWebAuth.SESSION_USER_ID] = compte_usager[ConstantesWebAuth.SESSION_USER_ID]
                session[ConstantesWebAuth.SESSION_USER_NAME] = nom_usager
            except KeyError:
                pass  # OK

            session[ConstantesWebAuth.SESSION_PASSKEY_AUTHENTICATION] = resultat_compte[ConstantesWebAuth.SESSION_PASSKEY_AUTHENTICATION]
            reponse_dict[ConstantesWebAuth.SESSION_AUTHENTICATION_CHALLENGE] = resultat_compte[ConstantesWebAuth.SESSION_AUTHENTICATION_CHALLENGE]

            if session.get(ConstantesWebAuth.SESSION_AUTHENTIFIEE) is True:
                # Si session deja active
                reponse_dict['auth'] = True
                try:
                    reponse_dict[ConstantesWebAuth.REPONSE_DELEGATIONS_DATE] = compte_usager[
                        ConstantesWebAuth.REPONSE_DELEGATIONS_DATE]
                    reponse_dict[ConstantesWebAuth.REPONSE_DELEGATIONS_VERSION] = compte_usager[
                        ConstantesWebAuth.REPONSE_DELEGATIONS_VERSION]
                except KeyError:
                    pass  # OK

            if generer_challenge:
                try:
                    reponse_dict[ConstantesWebAuth.SESSION_REGISTRATION_CHALLENGE] = resultat_compte[ConstantesWebAuth.SESSION_REGISTRATION_CHALLENGE]
                    session[ConstantesWebAuth.SESSION_REGISTRATION_CHALLENGE] = resultat_compte[ConstantesWebAuth.SESSION_REGISTRATION_CHALLENGE]
                    reponse_dict['methodesDisponibles'] = {'certificat': True}
                except KeyError:
                    pass  # OK

            # Tenter de transmettre certificat si nouvelle activation - TODO
            #     // Trouver activation. Privilegier activation du nouveau certificat (fingerprintPk)
            #     // Fallback sur certificat courant (fingerprintCourant)
            #     const activations = infoUsager.activations || {}
            #     let activation = activations[fingerprintPk]
            #     if(!activation) {
            #       activation = activations[fingerprintCourant]
            #     }
            #     if(activation) {
            #       // Filtrer methodes d'activation
            #       reponse.activation = {...activation, fingerprint: activation.fingerprint_pk, valide: true}
            #       if(reponse.activation.certificat) {
            #         // Extraire le certificat vers top du compte
            #         reponse.certificat = reponse.activation.certificat
            #         delete reponse.activation.certificat
            #       }
            #       reponse.methodesDisponibles = {certificat: true}
            #     } else if(socket.modeProtege === true) {
            #       reponse.methodesDisponibles = {certificat: true}
            #     }
            try:
                reponse_certificat = resultat[1]
                reponse_dict['certificat'] = reponse_certificat['certificat']
            except IndexError:
                try:
                    reponse_dict['certificat'] = resultat_compte['certificat']
                except KeyError:
                    pass  # OK

            # return web.json_response(reponse_originale)
            reponse_signee, correlation_id = self.etat.formatteur_message.signer_message(Constantes.KIND_REPONSE, reponse_dict)

            return web.json_response(reponse_signee)

    async def authentifier_usager(self, request: Request):
        async with self.__semaphore_authentifier:
            params = await request.json()

            # TODO - verifier webauthn

            session = await get_session(request)
            try:
                user_id = session[ConstantesWebAuth.SESSION_USER_ID]
                passkey_authentication = session[ConstantesWebAuth.SESSION_PASSKEY_AUTHENTICATION]
                challenge = passkey_authentication['ast']['challenge']
            except KeyError:
                reponse, correlation_id = self.etat.formatteur_message.signer_message(
                    Constantes.KIND_REPONSE, {'ok': False, 'err': 'session non initialisee via get_usager'})
                return web.json_response(reponse, status=401)

            commande = {
                'userId': user_id,
                'hostname': request.host,
                'challenge': challenge,
                'reponseWebauthn': params,
            }

            producer = await asyncio.wait_for(self.etat.producer_wait(), timeout=0.3)
            reponse_auth = await producer.executer_commande(
                commande, Constantes.DOMAINE_CORE_MAITREDESCOMPTES, 'authentifierWebauthn',
                exchange=Constantes.SECURITE_PUBLIC)

            reponse_parsed = reponse_auth.parsed
            if reponse_parsed['ok'] is not True:
                return web.HTTPUnauthorized()

            reponse_dict = {'userId': user_id, 'auth': True}

            try:
                reponse_dict['certificat'] = reponse_parsed['certificat']
            except KeyError:
                pass  # Ok

            session[ConstantesWebAuth.SESSION_AUTHENTIFIEE] = True

            #     if(resultatWebauthn.cookie) {
            #       debug("Retourner cookie de session %O", resultatWebauthn.cookie)
            #       session.cookieSession = resultatWebauthn.cookie
            #       session.save()
            #       reponse.cookie_disponible = true
            #     }

            # Signer la reponse
            reponse_signee, correlation = self.etat.formatteur_message.signer_message(Constantes.KIND_REPONSE, reponse_dict)

            response = web.json_response(reponse_signee)

            try:
                cookie_session = reponse_parsed['cookie']
                now = int(datetime.datetime.utcnow().timestamp())
                max_age = cookie_session['expiration'] - now
                box = nacl.secret.SecretBox(self.__session_encryption_key)
                cookie_encrypted = box.encrypt(cookie_session['challenge'].encode('utf-8'))
                cookie_b64 = base64.b64encode(cookie_encrypted).decode('utf-8')
                # response.set_cookie('mgsession', cookie_b64, max_age=max_age, httponly=True, secure=True, samesite='Strict', domain='/')
                response.set_cookie('mgsession', cookie_b64, max_age=max_age, httponly=True, secure=True)
            except KeyError:
                pass  # Pas de cookie

            return response

    async def deconnecter_usager(self, request: Request):
        async with self.__semaphore_verifier_usager:
            session = await get_session(request)
            session.invalidate()
            headers = {'Cache-Control': 'no-store'}
            return web.HTTPTemporaryRedirect('/millegrilles', headers=headers)

    async def verifier_usager_noauth(self, request: Request):
        return await self.__verifier_usager(request, noauth=True)

    async def verifier_usager(self, request: Request):
        return await self.__verifier_usager(request)

    async def __verifier_usager(self, request: Request, noauth=False):
        async with self.__semaphore_verifier_usager:
            session = await get_session(request)
            try:
                user_id = session[ConstantesWebAuth.SESSION_USER_ID]
                user_name = session[ConstantesWebAuth.SESSION_USER_NAME]
            except KeyError:
                # L'usager n'est pas authentifie
                if noauth:
                    # On ne bloque pas l'acces
                    return web.HTTPOk()
                return web.HTTPUnauthorized()

            headers = {
                ConstantesWeb.HEADER_USER_NAME: user_name,
                ConstantesWeb.HEADER_USER_ID: user_id,
            }

            if session.get(ConstantesWebAuth.SESSION_AUTHENTIFIEE) is True:
                return web.HTTPOk(headers=headers)

            return web.HTTPUnauthorized(headers=headers)

    async def verifier_client_tls(self, request: Request):
        async with self.__semaphore_verifier_tls:
            return web.HTTPUnauthorized()

