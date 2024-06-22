import asyncio
import datetime
import json
import secrets
from urllib.parse import urlparse, parse_qs, unquote

from typing import Optional

from aiohttp import web
from aiohttp.web_request import Request
from aiohttp_session import get_session
from certvalidator.errors import PathValidationError
from cryptography.exceptions import InvalidSignature
from cryptography.x509.extensions import ExtensionNotFound

import logging

from millegrilles_messages.messages import Constantes
from millegrilles_messages.messages.EnveloppeCertificat import EnveloppeCertificat
from millegrilles_web.WebServer import WebServer
from millegrilles_web import Constantes as ConstantesWeb
from millegrilles_webauth import Constantes as ConstantesWebAuth
from millegrilles_webauth.SessionCookieManager import SessionCookieManager
from millegrilles_web.JwtUtils import get_headers, verify


# DUREE_SESSION = 3_600 * 48
DUREE_SESSION = 3_600

LOGGER = logging.getLogger(__name__)


class WebServerAuth(WebServer):

    def __init__(self, etat, commandes):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        super().__init__(ConstantesWebAuth.WEBAPP_PATH, etat, commandes, duree_session=DUREE_SESSION)

        self.__semaphore_authentifier = asyncio.BoundedSemaphore(value=2)
        self.__semaphore_verifier_usager = asyncio.BoundedSemaphore(value=5)
        self.__semaphore_verifier_tls = asyncio.BoundedSemaphore(value=10)
        self.__cookie_manager = None

    def get_nom_app(self) -> str:
        return ConstantesWebAuth.APP_NAME

    async def setup(self, configuration: Optional[dict] = None, stop_event: Optional[asyncio.Event] = None):
        await super().setup(configuration, stop_event)
        redis_session = await self._connect_redis()
        self.__cookie_manager = SessionCookieManager(redis_session, self._etat)
        self._commandes.set_cookie_manager(self.__cookie_manager)

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
        self.app.router.add_get(f'/auth/verifier_usager_tls', self.verifier_usager_tls),
        self.app.router.add_get(f'/auth/verifier_any_tls', self.verifier_any_tls),

        # Routes speciales
        self.app.router.add_get(f'/auth/verifier_fuuid_jwt', self.verifier_fuuid_jwt),

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
                session_active = True
            else:
                etat_session = await self.__cookie_manager.ouvrir_session_cookie(request)
                if etat_session is False:
                    session_active = False
                elif nom_usager == etat_session.get('nomUsager'):
                    # Nom usager match - la session vient d'etre activee avec le cookie de session
                    user_id = compte_usager[ConstantesWebAuth.SESSION_USER_ID]
                    self.activer_session(session, user_id, nom_usager)
                    session_active = True
                else:
                    session_active = False

            if session_active:
                reponse_dict['auth'] = True
                try:
                    reponse_dict[ConstantesWebAuth.REPONSE_DELEGATIONS_DATE] = compte_usager[
                        ConstantesWebAuth.REPONSE_DELEGATIONS_DATE]
                    reponse_dict[ConstantesWebAuth.REPONSE_DELEGATIONS_VERSION] = compte_usager[
                        ConstantesWebAuth.REPONSE_DELEGATIONS_VERSION]
                    reponse_dict[ConstantesWebAuth.SESSION_USER_ID] = compte_usager[ConstantesWebAuth.SESSION_USER_ID]
                    reponse_dict[ConstantesWebAuth.SESSION_WEBAUTH_CREDENTIAL_COUNT] = resultat_compte.get(
                        ConstantesWebAuth.SESSION_WEBAUTH_CREDENTIAL_COUNT)
                except KeyError:
                    pass  # OK

            # Verifier si on a une authentification directe disponible pour la cle publique (PK) courante
            fingerprints = list()
            # Verifier si on a une activation pour la nouvelle cle, sinon pour la cle courante
            try:
                fingerprints.append(message['fingerprintPkNouveau'])
            except KeyError:
                pass  #
            try:
                fingerprints.append(message['fingerprintPkCourant'])
            except KeyError:
                pass  #

            for fingerprint_pk in fingerprints:
                activations = resultat_compte['activations']
                try:
                    activation_cle = activations[fingerprint_pk]
                except KeyError:
                    continue   # Pas d'activation pour ce certificat

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
                break

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

            mode_validation = None

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
                            mode_validation = 'activation'
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

                    # Supprimer les challenges apres succes pour eviter reutilisation
                    del session[ConstantesWebAuth.SESSION_PASSKEY_AUTHENTICATION]

                    reponse_dict = {'userId': user_id, 'auth': True}
                    mode_validation = 'webauthn'

                    try:
                        reponse_dict['certificat'] = reponse_parsed['certificat']
                    except KeyError:
                        pass  # Ok

            if not reponse_dict:
                # Acces refuse
                reponse, correlation_id = self.etat.formatteur_message.signer_message(
                    Constantes.KIND_REPONSE, {'ok': False, 'err': 'session non initialisee via get_usager'})
                return web.json_response(reponse, status=401)

            self.activer_session(session, user_id, nom_usager)

            # Signer la reponse
            reponse_signee, correlation = self.etat.formatteur_message.signer_message(Constantes.KIND_REPONSE, reponse_dict)

            response = web.json_response(reponse_signee)

            try:
                cookie_session = reponse_parsed['cookie']
            except (TypeError, KeyError):
                if mode_validation == 'activation':
                    # Creer un cookie d'activation
                    try:
                        duree_session = int(params['dureeSession'])
                    except (ValueError, KeyError):
                        duree_session = 86400
                    hostname = request.host
                    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=duree_session)
                    cookie_session = {
                        'user_id': user_id,
                        'challenge': challenge_certificate,
                        'expiration': int(expiration.timestamp()),
                        'hostname': hostname,
                    }
                else:
                    cookie_session = None  # Pas de cookie

            if cookie_session is not None:
                await self.__cookie_manager.set_cookie(nom_usager, cookie_session, response)

            return response

    async def deconnecter_usager(self, request: Request):
        async with self.__semaphore_verifier_usager:

            # Desactiver session
            session = await get_session(request)
            session.invalidate()
            headers = {'Cache-Control': 'no-store'}

            # Retirer cookie session
            response = web.HTTPTemporaryRedirect('/millegrilles', headers=headers)
            await self.__cookie_manager.desactiver_cookie(request, response)

            return response

    async def verifier_usager_noauth(self, request: Request):
        """
        Verifier si la session usager existe. Retourne toujours HTTP Status 200.
        :param request:
        :return: Response avec HTTP Status 200
        """
        try:
            return await self.__verifier_usager(request, noauth=True)
        except Exception:
            self.__logger.exception("Erreur verifier usager")
            return web.HTTPForbidden()

    async def verifier_usager(self, request: Request):
        """
        Verifier si la session usager exite.
        :param request:
        :return: Response avec HTTP Status 200 si existe, 401 si n'existe pas.
        """
        try:
            return await self.__verifier_usager(request)
        except:
            self.__logger.exception("Erreur verifier usager")
            return web.HTTPForbidden()

    async def __verifier_usager(self, request: Request, noauth=False):
        headers_base = {'Cache-Control': 'no-store'}

        user_name = None
        user_id = None

        async with self.__semaphore_verifier_usager:
            session = await get_session(request)

            if session.get(ConstantesWebAuth.SESSION_AUTHENTIFIEE) is True:
                try:
                    user_id = session[ConstantesWebAuth.SESSION_USER_ID]
                    user_name = session[ConstantesWebAuth.SESSION_USER_NAME]
                    auth_status = '1'
                except KeyError:
                    # L'usager n'est pas authentifie
                    if noauth:
                        # On ne bloque pas l'acces
                        return web.HTTPOk(headers=headers_base)
                    return web.HTTPForbidden(headers=headers_base)

            else:
                etat_session = await self.__cookie_manager.ouvrir_session_cookie(request)
                if etat_session is False:
                    auth_status = '0'
                elif isinstance(etat_session, dict):
                    # etat_session est un str (nom_usager) - la session vient d'etre activee avec le cookie de session
                    user_name = etat_session['nomUsager']
                    user_id = etat_session['user_id']
                    self.activer_session(session, user_id, user_name)
                    auth_status = '1'
                else:
                    auth_status = '0'

            headers = {
                'Cache-Control': 'no-store',
                ConstantesWeb.HEADER_AUTH: auth_status,
            }
            if user_id:
                headers[ConstantesWeb.HEADER_USER_ID] = user_id
            if user_name:
                headers[ConstantesWeb.HEADER_USER_NAME] = user_name

            if session.get(ConstantesWebAuth.SESSION_AUTHENTIFIEE) is True:
                return web.HTTPOk(headers=headers)
            elif noauth is True:
                # Utilise pour socket.io, ne pas retourner info usager
                # (indique implicitement que l'authentification est completee)
                return web.HTTPOk(headers=headers_base)

            return web.HTTPForbidden(headers=headers)

    async def verifier_client_tls(self, request: Request):
        async with self.__semaphore_verifier_tls:
            self.__logger.debug("verifier_client_tls URL %s" % request.url)
            for key, value in request.headers.items():
                self.__logger.debug("TLS Header %s = %s" % (key, value))

            try:
                verified = request.headers['VERIFIED']
                if verified != 'SUCCESS':
                    # Invalide - aurait du etre rejete par nginx
                    return web.HTTPUnauthorized()
                cert = request.headers['X-SSL-CERT']
            except KeyError:
                self.__logger.warning("Requete tls sans certificat : %s" % request.url)
                return web.HTTPUnauthorized()

            try:
                cert = unquote(cert)
                enveloppe = EnveloppeCertificat.from_pem(cert)
            except Exception:
                # Erreur chargement PEM
                return web.HTTPUnauthorized()

            # if verified != 'SUCCESS':
            #     # Reload le certificat complet (chaine) a partir de redis ou CorePki
            #     fingerprint = enveloppe.fingerprint
            #     enveloppe = await self.etat.charger_certificat(fingerprint)
            #
            #     if not enveloppe.est_verifie:
            #         # Certificat invalide
            #         return web.HTTPUnauthorized()

            # Seul un certificat systeme (avec au moins 1 exchange) peut utiliser TLS
            # try:
            #     exchanges = enveloppe.get_exchanges
            #     if exchanges is None:
            #         return web.HTTPUnauthorized()
            # except ExtensionNotFound:
            #     # Verifier si c'est un certificat nginx (seule exception)
            #     try:
            #         roles = enveloppe.get_roles
            #         if 'nginx' not in roles:
            #             self.__logger.debug("Certificat sans exchanges et role != nginx - REFUSE")
            #             return web.HTTPUnauthorized()
            #     except ExtensionNotFound:
            #         self.__logger.debug("Certificat sans exchanges et role != nginx - REFUSE")
            #         return web.HTTPUnauthorized()

            # Seul un certificat systeme (avec au moins 1 exchange) peut utiliser client TLS
            try:
                verifier_certificat_exchange(enveloppe)
            except CertificatPasExchange:
                return web.HTTPForbidden()

            return web.HTTPOk()

    async def verifier_usager_tls(self, request: Request):
        async with self.__semaphore_verifier_tls:
            self.__logger.debug("verifier_usager_tls URL %s" % request.url)
            for key, value in request.headers.items():
                self.__logger.debug("TLS Header %s = %s" % (key, value))

            try:
                verified = request.headers['VERIFIED']
                if verified != 'SUCCESS':
                    # Invalide - aurait du etre rejete par nginx
                    return web.HTTPBadRequest()
                cert = request.headers['X-SSL-CERT']
            except KeyError:
                self.__logger.warning("Requete tls sans certificat : %s" % request.url)
                return web.HTTPBadRequest()

            try:
                cert = unquote(cert)
                enveloppe = EnveloppeCertificat.from_pem(cert)
            except Exception:
                # Erreur chargement PEM
                return web.HTTPBadRequest()

            # try:
            #     user_id = enveloppe.get_user_id
            #     user_name = enveloppe.subject_common_name
            #     if user_name is None or user_id is None:
            #         self.__logger.debug("Certificat usager sans user_id - REFUSE")
            #         return web.HTTPUnauthorized()
            # except ExtensionNotFound:
            #     self.__logger.debug("Certificat sans exchanges et role != nginx - REFUSE")
            #     return web.HTTPUnauthorized()

            # Verifier si on a un certificat usager (navigateur)
            try:
                user_id, user_name = verifier_certificat_usager(enveloppe)
            except CertificatPasUsager:
                return web.HTTPForbidden()

            auth_status = '1'
            headers = {
                'Cache-Control': 'no-store',
                ConstantesWeb.HEADER_AUTH: auth_status,
                ConstantesWeb.HEADER_USER_ID: user_id,
                ConstantesWeb.HEADER_USER_NAME: user_name,
            }

            return web.HTTPOk(headers=headers)

    async def verifier_any_tls(self, request: Request):
        """
        Permet un certificat systeme (avec exchanges) ou usager (avec role navigateur et user_id)
        :param request:
        :return:
        """
        async with self.__semaphore_verifier_tls:
            self.__logger.debug("verifier_any_tls URL %s" % request.url)

        async with self.__semaphore_verifier_tls:
            self.__logger.debug("verifier_usager_tls URL %s" % request.url)
            for key, value in request.headers.items():
                self.__logger.debug("TLS Header %s = %s" % (key, value))

            try:
                verified = request.headers['VERIFIED']
                if verified != 'SUCCESS':
                    # Invalide - aurait du etre rejete par nginx
                    return web.HTTPUnauthorized()
                cert = request.headers['X-SSL-CERT']
            except KeyError:
                self.__logger.warning("Requete tls sans certificat : %s" % request.url)
                return web.HTTPUnauthorized()

            try:
                cert = unquote(cert)
                enveloppe = EnveloppeCertificat.from_pem(cert)
            except Exception:
                # Erreur chargement PEM
                return web.HTTPUnauthorized()

            # Seul un certificat systeme (avec au moins 1 exchange) peut utiliser TLS
            # Verifier si c'est un certificat nginx (seule exception)
            try:
                user_id, user_name = verifier_certificat_usager(enveloppe)
            except CertificatPasUsager:
                pass
            else:
                auth_status = '1'
                headers = {
                    'Cache-Control': 'no-store',
                    ConstantesWeb.HEADER_AUTH: auth_status,
                    ConstantesWeb.HEADER_USER_ID: user_id,
                    ConstantesWeb.HEADER_USER_NAME: user_name,
                }
                return web.HTTPOk(headers=headers)

            try:
                verifier_certificat_exchange(enveloppe)
            except CertificatPasExchange:
                return web.HTTPForbidden()
            else:
                return web.HTTPOk()

    def activer_session(self, session, user_id: str, nom_usager: str):
        self.__logger.debug("Activer session pour %s/%s" % (nom_usager, user_id))
        session[ConstantesWebAuth.SESSION_AUTHENTIFIEE] = True
        session[ConstantesWebAuth.SESSION_USER_ID] = user_id
        session[ConstantesWebAuth.SESSION_USER_NAME] = nom_usager

    async def verifier_fuuid_jwt(self, request: Request):
        async with self.__semaphore_verifier_usager:
            headers_base = {'Cache-Control': 'no-store'}
            auth_status = '0'
            session = await get_session(request)

            if session.get(ConstantesWebAuth.SESSION_AUTHENTIFIEE) is True:
                try:
                    user_id = session[ConstantesWebAuth.SESSION_USER_ID]
                    user_name = session[ConstantesWebAuth.SESSION_USER_NAME]
                    auth_status = '1'

                    headers = {
                        'Cache-Control': 'no-store',
                        ConstantesWeb.HEADER_USER_NAME: user_name,
                        ConstantesWeb.HEADER_USER_ID: user_id,
                        ConstantesWeb.HEADER_AUTH: auth_status,
                    }

                    # Ok, session existe.
                    return web.HTTPOk(headers=headers)
                except KeyError:
                    # L'usager n'est pas authentifie. Utiliser le token JWT.
                    pass

            # La session n'existe pas
            # Extraire token et valider avec certificat de signature
            try:
                url_original = urlparse(request.headers['X-Original-URI'])
                query_params = parse_qs(url_original.query)
                token = query_params.get('jwt')[0]
                headers_token = get_headers(token)
                fingerprint_certificat = headers_token['kid']
            except Exception as e:
                self.__logger.debug("Erreur verification token JWT : %s" % str(e))
                return web.HTTPUnauthorized(headers=headers_base)

            # Charger le certificat
            try:
                enveloppe = await self.etat.charger_certificat(fingerprint_certificat)
            except Exception as e:
                self.__logger.debug("Erreur chargement certificat fingerprint %s : %s " % (fingerprint_certificat, str(e)))
                return web.HTTPUnauthorized(headers=headers_base)

            try:
                resultat = verify(enveloppe, token)
                user_id = resultat['userId']
                headers = {
                    'Cache-Control': 'no-store',
                    ConstantesWeb.HEADER_USER_ID: user_id,
                    # ConstantesWeb.HEADER_USER_NAME: user_name,
                    ConstantesWeb.HEADER_AUTH: auth_status,
                }
                return web.HTTPOk(headers=headers)
            except Exception as e:
                self.__logger.debug("Erreur chargement certificat fingerprint %s : %s " % (
                    fingerprint_certificat, str(e)))
                return web.HTTPUnauthorized(headers=headers_base)

    async def supprimer_cookies_usager(self, user_id):
        return await self.__cookie_manager.supprimer_cookies_usager(user_id)


def verifier_certificat_exchange(enveloppe: EnveloppeCertificat):
    try:
        exchanges = enveloppe.get_exchanges
        if exchanges is None or len(exchanges) == 0:
            raise CertificatPasExchange()
        return True
    except ExtensionNotFound:
        # Verifier si c'est un certificat nginx (seule exception)
        try:
            roles = enveloppe.get_roles
            if 'nginx' not in roles:
                LOGGER.debug("Certificat sans exchanges et role != nginx - REFUSE")
                raise CertificatPasExchange()
            return True
        except ExtensionNotFound:
            LOGGER.debug("Certificat sans exchanges et role != nginx - REFUSE")
            raise CertificatPasExchange()


def verifier_certificat_usager(enveloppe: EnveloppeCertificat) -> (str, str):
    try:
        user_id = enveloppe.get_user_id
        user_name = enveloppe.subject_common_name
        roles = enveloppe.get_roles
        if user_name is None or user_id is None:
            LOGGER.debug("Certificat usager sans user_id - REFUSE")
            raise CertificatPasUsager()
        if 'navigateur' not in roles:
            LOGGER.debug("Certificat usager sans role navigateur - REFUSE")
            raise CertificatPasUsager()
    except ExtensionNotFound:
        LOGGER.debug("Certificat sans user_id/roles - REFUSE")
        raise CertificatPasUsager()


class CertificatPasUsager(Exception):
    pass


class CertificatPasExchange(Exception):
    pass
