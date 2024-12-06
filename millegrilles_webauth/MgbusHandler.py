import logging

from asyncio import TaskGroup
from typing import Optional, Callable, Coroutine, Any

from cryptography.x509 import ExtensionNotFound

from millegrilles_messages.bus.BusContext import MilleGrillesBusContext, ForceTerminateExecution
from millegrilles_messages.messages import Constantes
from millegrilles_messages.bus.PikaChannel import MilleGrillesPikaChannel
from millegrilles_messages.bus.PikaQueue import MilleGrillesPikaQueueConsumer, RoutingKey
from millegrilles_messages.messages.MessagesModule import MessageWrapper
from millegrilles_webauth.WebauthManager import WebauthManager


class MgbusHandler:
    """
    MQ access module
    """

    def __init__(self, manager: WebauthManager):
        super().__init__()
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)
        self.__manager = manager
        self.__task_group: Optional[TaskGroup] = None

    async def run(self):
        self.__logger.debug("MgbusHandler thread started")
        try:
            await self.__register()

            async with TaskGroup() as group:
                self.__task_group = group
                group.create_task(self.__stop_thread())
                group.create_task(self.__manager.context.bus_connector.run())

        except *Exception:  # Stop on any thread exception
            if self.__manager.context.stopping is False:
                self.__logger.exception("GenerateurCertificatsHandler Unhandled error, closing")
                self.__manager.context.stop()
                raise ForceTerminateExecution()
        self.__task_group = None
        self.__logger.debug("MgbusHandler thread done")

    async def __stop_thread(self):
        await self.__manager.context.wait()

    async def __register(self):
        self.__logger.info("Register with the MQ Bus")

        context = self.__manager.context

        channel_exclusive = create_exclusive_q_channel(context, self.__on_exclusive_message)
        await self.__manager.context.bus_connector.add_channel(channel_exclusive)

    async def __on_exclusive_message(self, message: MessageWrapper):
        # Authorization check
        enveloppe = message.certificat
        try:
            domaines = enveloppe.get_domaines
        except ExtensionNotFound:
            domaines = list()
        try:
            exchanges = enveloppe.get_exchanges
        except ExtensionNotFound:
            exchanges = list()

        action = message.routage['action']

        if Constantes.SECURITE_PROTEGE in exchanges:
            if Constantes.DOMAINE_CORE_MAITREDESCOMPTES in domaines and action == Constantes.EVENEMENT_EVICT_USAGER:
                return await self.__manager.evict_user_message(message)

        self.__logger.info("on_exclusive_message Ignoring unknown action %s", message.routing_key)



def create_exclusive_q_channel(context: MilleGrillesBusContext,
                               on_message: Callable[[MessageWrapper], Coroutine[Any, Any, None]]) -> MilleGrillesPikaChannel:
    q_channel = MilleGrillesPikaChannel(context, prefetch_count=20)
    q_instance = MilleGrillesPikaQueueConsumer(context, on_message, None, exclusive=True, arguments={'x-message-ttl': 30_000})

    q_instance.add_routing_key(RoutingKey(
        Constantes.SECURITE_PUBLIC, f'evenement.{Constantes.DOMAINE_CORE_MAITREDESCOMPTES}.{Constantes.EVENEMENT_EVICT_USAGER}'))

    q_channel.add_queue(q_instance)
    return q_channel
