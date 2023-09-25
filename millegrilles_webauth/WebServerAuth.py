import logging

from millegrilles_web.WebServer import WebServer

from millegrilles_webauth import Constantes as ConstantesWebAuth


class WebServerAuth(WebServer):

    def __init__(self, etat, commandes):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        super().__init__(ConstantesWebAuth.WEBAPP_PATH, etat, commandes)

    def get_nom_app(self) -> str:
        return ConstantesWebAuth.APP_NAME

    async def setup_socketio(self):
        # Ne pas initialiser socket.io
        pass

    async def _preparer_routes(self):
        self.__logger.info("Preparer routes %s sous /%s" % (self.__class__.__name__, self.get_nom_app()))
        await super()._preparer_routes()
