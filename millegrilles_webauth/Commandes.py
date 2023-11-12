import logging

from cryptography.x509.extensions import ExtensionNotFound

from millegrilles_messages.messages import Constantes as ConstantesMillegrilles
from millegrilles_messages.messages.MessagesThread import MessagesThread
from millegrilles_messages.messages.MessagesModule import MessageProducerFormatteur, MessageWrapper, RessourcesConsommation

from millegrilles_web.Commandes import CommandHandler


class CommandWebAuthHandler(CommandHandler):

    def __init__(self, web_app):
        super().__init__(web_app)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__cookie_manager = None

    def set_cookie_manager(self, cookie_manager):
        self.__cookie_manager = cookie_manager

    async def supprimer_cookies_user_id(self, message: MessageWrapper):
        user_id = message.parsed['userId']
        return await self.__cookie_manager.supprimer_cookies_usager(user_id)

    def configurer_consumers(self, messages_thread: MessagesThread):
        super().configurer_consumers(messages_thread)

        res_evenements = RessourcesConsommation(self.callback_reply_q, channel_separe=True, est_asyncio=True)
        res_evenements.ajouter_rk(
            ConstantesMillegrilles.SECURITE_PUBLIC,
            f'evenement.{ConstantesMillegrilles.DOMAINE_CORE_MAITREDESCOMPTES}.{ConstantesMillegrilles.EVENEMENT_EVICT_USAGER}', )

        messages_thread.ajouter_consumer(res_evenements)

    async def traiter_commande(self, producer: MessageProducerFormatteur, message: MessageWrapper):
        routing_key = message.routing_key
        exchange = message.exchange
        action = routing_key.split('.').pop()
        type_message = routing_key.split('.')[0]
        enveloppe = message.certificat

        try:
            exchanges = enveloppe.get_exchanges
        except ExtensionNotFound:
            exchanges = list()

        try:
            roles = enveloppe.get_roles
        except ExtensionNotFound:
            roles = list()

        try:
            user_id = enveloppe.get_user_id
        except ExtensionNotFound:
            user_id = list()

        try:
            delegation_globale = enveloppe.get_delegation_globale
        except ExtensionNotFound:
            delegation_globale = None

        if type_message == 'evenement':
            if exchange == ConstantesMillegrilles.SECURITE_PUBLIC:
                if action == ConstantesMillegrilles.EVENEMENT_EVICT_USAGER:
                    await self.supprimer_cookies_user_id(message)
                    return False

        # Fallback sur comportement de la super classe
        return await super().traiter_commande(producer, message)

    async def traiter_cedule(self, producer: MessageProducerFormatteur, message: MessageWrapper):
        await super().traiter_cedule(producer, message)

        # contenu = message.parsed
        # date_cedule = datetime.datetime.fromtimestamp(contenu['estampille'], tz=pytz.UTC)
        #
        # now = datetime.datetime.now(tz=pytz.UTC)
        # if now - datetime.timedelta(minutes=2) > date_cedule:
        #     return  # Vieux message de cedule
        #
        # weekday = date_cedule.weekday()
        # hour = date_cedule.hour
        # minute = date_cedule.minute
        #
        # if weekday == 0 and hour == 4:
        #     pass
        # elif minute % 20 == 0:
        #     pass

