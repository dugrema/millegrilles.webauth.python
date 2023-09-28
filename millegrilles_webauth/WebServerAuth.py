import asyncio
import base64
import datetime
import json
import nacl.secret
import nacl.utils
import secrets

from aiohttp import web
from aiohttp.web_request import Request
from aiohttp_session import get_session
from certvalidator.errors import PathValidationError
from cryptography.exceptions import InvalidSignature

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
            if compte_usager is None:
                # Le compte est vide, retourner reponse directement
                reponse_signee, correlation_id = self.etat.formatteur_message.signer_message(Constantes.KIND_REPONSE,
                                                                                             compte_usager)
                return web.json_response(reponse_signee)
            # reponse_originale = compte_usager['__original']

            reponse_dict = dict()

            # Conserver information dans la session au besoin
            session = await get_session(request)
            session.changed()

            try:
                # Conserver passkey et user_id pour verifier lors de l'authentification
                session[ConstantesWebAuth.SESSION_PASSKEY_AUTHENTICATION] = resultat_compte[ConstantesWebAuth.SESSION_PASSKEY_AUTHENTICATION]
                session[ConstantesWebAuth.SESSION_USER_ID_CHALLENGE] = compte_usager[ConstantesWebAuth.SESSION_USER_ID]
                session[ConstantesWebAuth.SESSION_USER_NAME_CHALLENGE] = nom_usager
                reponse_dict[ConstantesWebAuth.SESSION_AUTHENTICATION_CHALLENGE] = resultat_compte[ConstantesWebAuth.SESSION_AUTHENTICATION_CHALLENGE]
                reponse_dict['methodesDisponibles'] = {'certificat': True}
            except KeyError:
                pass  # L'usager n'a aucune cle webauthn

            if session.get(ConstantesWebAuth.SESSION_AUTHENTIFIEE) is True:
                # Si session deja active
                reponse_dict['auth'] = True
                try:
                    reponse_dict[ConstantesWebAuth.REPONSE_DELEGATIONS_DATE] = compte_usager[
                        ConstantesWebAuth.REPONSE_DELEGATIONS_DATE]
                    reponse_dict[ConstantesWebAuth.REPONSE_DELEGATIONS_VERSION] = compte_usager[
                        ConstantesWebAuth.REPONSE_DELEGATIONS_VERSION]
                    reponse_dict[ConstantesWebAuth.SESSION_USER_ID] = compte_usager[ConstantesWebAuth.SESSION_USER_ID]
                except KeyError:
                    pass  # OK

            try:
                # Verifier si on a une authentification directe disponible pour la cle publique (PK) courante
                fingerprint_pk = message['fingerprintPkCourant']
                activations = resultat_compte['activations']
                activation_cle = activations[fingerprint_pk]
                if activation_cle.get('certificat') is not None:
                    reponse_dict['certificat'] = activation_cle['certificat']

                # Generer un challenge d'auth via certificat
                challenge = secrets.token_urlsafe(32)

                session[ConstantesWebAuth.SESSION_USER_ID_CHALLENGE] = compte_usager[
                    ConstantesWebAuth.SESSION_USER_ID]
                session[ConstantesWebAuth.SESSION_USER_NAME_CHALLENGE] = nom_usager
                session[ConstantesWebAuth.SESSION_CERTIFICATE_CHALLENGE] = challenge
                reponse_dict['challenge_certificat'] = challenge

                # Flags qui indiquent au client qu'il peut s'authentifier avec certificat sans webauthn
                reponse_dict['methodesDisponibles'] = {
                    'certificat': True,
                    'activation': True,
                }

            except KeyError:
                pass  # OK

            # if generer_challenge:
            #     try:
            #         reponse_dict[ConstantesWebAuth.SESSION_REGISTRATION_CHALLENGE] = resultat_compte[ConstantesWebAuth.SESSION_REGISTRATION_CHALLENGE]
            #         session[ConstantesWebAuth.SESSION_REGISTRATION_CHALLENGE] = resultat_compte[ConstantesWebAuth.SESSION_REGISTRATION_CHALLENGE]
            #     except KeyError:
            #         pass  # OK

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
        """
        Authentification de l'usager.

        Noter qu'il faut faire un appel a get_usager avec le nom_usager pour initialiser la session prealablement.
        C'est la seule methode pour obtenir correctement un challenge d'authentification (webauthn ou activation avec certificat).

        :param request:
        :return:
        """

        async with self.__semaphore_authentifier:
            params = await request.json()

            try:
                # Extraire le contenu des params si c'est un message signe
                enveloppe = await self.etat.validateur_message.verifier(params)
                params = json.loads(params['contenu'])
                signature_ok = True
            except (KeyError, PathValidationError, InvalidSignature):
                enveloppe = None
                signature_ok = False

            session = await get_session(request)

            # Determiner si on authentifie via webauthn ou activation (certificat)
            challenge_webauthn = None
            reponse_dict = None
            reponse_parsed = None
            nom_usager = None

            if signature_ok and enveloppe:
                # Verifier si on une activation par certificat (bypass webauthn)
                # Le message doit etre bien formatte et signe
                try:
                    challenge_certificate = params[ConstantesWebAuth.SESSION_CERTIFICATE_CHALLENGE]
                except (KeyError, PathValidationError, InvalidSignature):
                    reponse_dict = None
                else:
                    # Le challenge recu doit correspondre challenge conserve dans la session
                    challenge_session = session[ConstantesWebAuth.SESSION_CERTIFICATE_CHALLENGE]
                    if challenge_session == challenge_certificate:
                        user_id_challenge = session[ConstantesWebAuth.SESSION_USER_ID_CHALLENGE]
                        nom_usager_challenge = session[ConstantesWebAuth.SESSION_USER_NAME_CHALLENGE]
                        user_id = enveloppe.get_user_id
                        nom_usager = enveloppe.subject_common_name
                        if user_id == user_id_challenge and nom_usager == nom_usager_challenge:
                            reponse_dict = {'userId': user_id, 'auth': True}
                        else:
                            # Acces refuse
                            reponse_dict = None
                    else:
                        # Acces refuse
                        reponse_dict = None

            if reponse_dict is None:
                # On n'est pas en mode d'authentification avec certificat / activation de compte
                try:
                    # Verifier si on utilise la signature webauthn
                    passkey_authentication = session[ConstantesWebAuth.SESSION_PASSKEY_AUTHENTICATION]
                    challenge_webauthn = passkey_authentication['ast']['challenge']
                    user_id = session[ConstantesWebAuth.SESSION_USER_ID_CHALLENGE]
                    nom_usager = session[ConstantesWebAuth.SESSION_USER_NAME_CHALLENGE]
                    # TODO - verifier webauthn avant appel serveur
                    # if not valide:
                    #     challenge_webauthn = None
                    #     reponse_dict = None
                except (TypeError, KeyError):
                    reponse_dict = None
                else:
                    # Authentifier via webauthn
                    commande = {
                        'userId': user_id,
                        'hostname': request.host,
                        'challenge': challenge_webauthn,
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

            if not reponse_dict:
                # Acces refuse
                reponse, correlation_id = self.etat.formatteur_message.signer_message(
                    Constantes.KIND_REPONSE, {'ok': False, 'err': 'session non initialisee via get_usager'})
                return web.json_response(reponse, status=401)

            session[ConstantesWebAuth.SESSION_AUTHENTIFIEE] = True
            session[ConstantesWebAuth.SESSION_USER_ID] = user_id
            session[ConstantesWebAuth.SESSION_USER_NAME] = nom_usager

            # Signer la reponse
            reponse_signee, correlation = self.etat.formatteur_message.signer_message(Constantes.KIND_REPONSE, reponse_dict)

            response = web.json_response(reponse_signee)

            try:
                cookie_session = reponse_parsed['cookie']
            except (TypeError, KeyError):
                pass  # Pas de cookie
            else:
                now = int(datetime.datetime.utcnow().timestamp())
                try:
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
        headers_base = {'Cache-Control': 'no-store'}

        async with self.__semaphore_verifier_usager:
            session = await get_session(request)
            try:
                user_id = session[ConstantesWebAuth.SESSION_USER_ID]
                user_name = session[ConstantesWebAuth.SESSION_USER_NAME]
            except KeyError:
                # L'usager n'est pas authentifie
                if noauth:
                    # On ne bloque pas l'acces
                    return web.HTTPOk(headers=headers_base)
                return web.HTTPUnauthorized(headers=headers_base)

            if session.get(ConstantesWebAuth.SESSION_AUTHENTIFIEE) is True:
                auth_status = '1'
            else:
                auth_status = '0'

            headers = {
                'Cache-Control': 'no-store',
                ConstantesWeb.HEADER_USER_NAME: user_name,
                ConstantesWeb.HEADER_USER_ID: user_id,
                ConstantesWeb.HEADER_AUTH: auth_status,
            }

            if session.get(ConstantesWebAuth.SESSION_AUTHENTIFIEE) is True:
                return web.HTTPOk(headers=headers)
            elif noauth is True:
                # Utilise pour socket.io, ne pas retourner info usager
                # (indique implicitement que l'authentificaiton est completee)
                return web.HTTPOk(headers=headers_base)

            return web.HTTPUnauthorized(headers=headers)

    async def verifier_client_tls(self, request: Request):
        async with self.__semaphore_verifier_tls:
            return web.HTTPUnauthorized()

