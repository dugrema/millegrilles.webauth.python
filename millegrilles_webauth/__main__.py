import asyncio
import logging
from asyncio import TaskGroup
from concurrent.futures.thread import ThreadPoolExecutor

from typing import Awaitable

from millegrilles_messages.bus.BusContext import ForceTerminateExecution, StopListener
from millegrilles_messages.bus.PikaConnector import MilleGrillesPikaConnector
from millegrilles_web.Configuration import WebAppConfiguration
from millegrilles_webauth.MgbusHandler import MgbusHandler
from millegrilles_webauth.SessionCookieManager import SessionCookieManager
from millegrilles_webauth.WebServerAuth import WebServerAuth
from millegrilles_webauth.WebauthContext import WebauthContext
from millegrilles_webauth.WebauthManager import WebauthManager

LOGGER = logging.getLogger(__name__)


async def force_terminate_task_group():
    """Used to force termination of a task group."""
    raise ForceTerminateExecution()


async def main():
    config = WebAppConfiguration.load()
    context = WebauthContext(config)

    LOGGER.setLevel(logging.INFO)
    LOGGER.info("Starting")

    # Wire classes together, gets awaitables to run
    coros = await wiring(context)

    try:
        # Use taskgroup to run all threads
        async with TaskGroup() as group:
            for coro in coros:
                group.create_task(coro)

            # Create a listener that fires a task to cancel all other tasks
            async def stop_group():
                group.create_task(force_terminate_task_group())
            stop_listener = StopListener(stop_group)
            context.register_stop_listener(stop_listener)

    except* (ForceTerminateExecution, asyncio.CancelledError):
        pass  # Result of the termination task


async def wiring(context: WebauthContext) -> list[Awaitable]:
    # Some threads get used to handle sync events for the duration of the execution. Ensure there are enough.
    loop = asyncio.get_event_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=10))

    # Service instances
    bus_connector = MilleGrillesPikaConnector(context)
    session_cookie_handler = SessionCookieManager(context)

    # Facade
    manager = WebauthManager(context, session_cookie_handler)
    redis_client = await manager.connect_redis()

    # Access modules
    web_server = WebServerAuth(manager)
    bus_handler = MgbusHandler(manager)

    # Setup, injecting additional dependencies
    context.bus_connector = bus_connector
    context.redis_client = redis_client
    await web_server.setup()
    await session_cookie_handler.setup()

    # Create tasks
    coros = [
        context.run(),
        web_server.run(),
        bus_handler.run(),
    ]

    return coros


if __name__ == '__main__':
    asyncio.run(main())
    LOGGER.info("Stopped")


# import argparse
# import asyncio
# import logging
# import signal
#
# from millegrilles_web.WebAppMain import WebAppMain
#
# from millegrilles_web.WebAppMain import LOGGING_NAMES as LOGGING_NAMES_WEB, adjust_logging
# from millegrilles_webauth.WebServerAuth import WebServerAuth
# from millegrilles_webauth.Commandes import CommandWebAuthHandler
#
# logger = logging.getLogger(__name__)
#
# LOGGING_NAMES = ['millegrilles_webauth']
# LOGGING_NAMES.extend(LOGGING_NAMES_WEB)
#
#
# class WebAuthAppMain(WebAppMain):
#
#     def __init__(self):
#         self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
#         super().__init__()
#
#     def init_command_handler(self) -> CommandWebAuthHandler:
#         return CommandWebAuthHandler(self)
#
#     async def configurer(self):
#         await super().configurer()
#
#     async def configurer_web_server(self):
#         self._web_server = WebServerAuth(self.etat, self._commandes_handler)
#         await self._web_server.setup(stop_event=self._stop_event)
#
#     def exit_gracefully(self, signum=None, frame=None):
#         self.__logger.info("Fermer application, signal: %d" % signum)
#         self._stop_event.set()
#
#     def parse(self) -> argparse.Namespace:
#         args = super().parse()
#         adjust_logging(LOGGING_NAMES, args)
#         return args
#
#
# async def demarrer():
#     main_inst = WebAuthAppMain()
#
#     signal.signal(signal.SIGINT, main_inst.exit_gracefully)
#     signal.signal(signal.SIGTERM, main_inst.exit_gracefully)
#
#     await main_inst.configurer()
#     logger.info("Run main webauth")
#     await main_inst.run()
#     logger.info("Fin main webauth")
#
#
# def main():
#     """
#     Methode d'execution de l'application
#     :return:
#     """
#     logging.basicConfig()
#     for log in LOGGING_NAMES:
#         logging.getLogger(log).setLevel(logging.INFO)
#     asyncio.run(demarrer())
#
#
# if __name__ == '__main__':
#     main()
