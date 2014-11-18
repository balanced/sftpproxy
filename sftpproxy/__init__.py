from __future__ import unicode_literals
import time
import logging
import functools
import threading
import SocketServer

import paramiko
import Crypto.Random

logger = logging.getLogger(__name__)

__version__ = '0.0.0'


class SFTPServerInterface(paramiko.SFTPServerInterface):

    def __init__(self, server, *args, **kwargs):
        self.client_address = server.client_address
        self.proxy = server.proxy
        self.username = self.proxy.config.username or server.username
        self.password = self.proxy.config.password or server.password
        super(SFTPServerInterface, self).__init__(server, *args, **kwargs)

    # TODO:


class ServerInterface(paramiko.ServerInterface):

    def __init__(self, server, client_address):
        self.client_address = client_address
        self.proxy = None
        self.username = None
        self.password = None
        self.key = None

    # TODO:


class SFTPRequestHandler(SocketServer.StreamRequestHandler):

    negotiation_poll = 0.1

    negotiation_timeout = 60

    auth_timeout = 60

    join_timeout = 10

    Interface = SFTPServerInterface
    
    Server = ServerInterface

    def __init__(
        self,
        request,
        client_address,
        server,
        host_key,
    ):
        self.host_key = host_key
        SocketServer.StreamRequestHandler.__init__(
            self, request, client_address, server,
        )

    @property
    def client_address_str(self):
        return ':'.join(map(str, self.client_address))

    def handle(self):
        logger.info('Connection made from %s', self.client_address_str)
        # proxy protocol
        client_address = self.client_address

        # transport
        transport = paramiko.Transport(self.request)
        if self.host_key is not None:
            transport.add_server_key(self.host_key)
        transport.set_subsystem_handler(
            'sftp',
            paramiko.SFTPServer,
            self.Interface,
        )

        try:
            # serve
            event = threading.Event()
            transport.start_server(
                event=event,
                server=self.Server(self.server, client_address),
            )

            # negotiate
            start = time.time()
            while True:
                if event.wait(self.negotiation_poll):
                    if not transport.is_active():
                        ex = transport.get_exception() or 'Negotiation failed.'
                        logger.warning(
                            '%r, disconnecting - %s',
                            self.client_address_str,
                            ex,
                        )
                        return
                    logger.debug('negotiation was OK')
                    break
                if (
                    self.negotiation_timeout is not None and
                    time.time() - start > self.negotiation_timeout
                ):
                    logger.warning(
                        '%r, disconnecting - Negotiation timedout.',
                        self.client_address_str,
                    )
                    return

            # accepted
            channel = transport.accept(self.auth_timeout)
            if channel is None:
                logger.warning(
                    '%r, disconnecting - auth failed, channel is None.',
                    self.client_address,
                )
                return

            # command(s)
            while transport.isAlive():
                transport.join(timeout=self.join_timeout)
        finally:
            logger.info(
                '%r, cleaning up connection - Bye.',
                self.client_address_str,
            )
            transport.close()
        # TODO:


class Server(SocketServer.TCPServer):

    def __init__(self, address, host_key):
        SocketServer.TCPServer.__init__(
            self,
            address,
            functools.partial(SFTPRequestHandler, host_key=host_key)
        )

    allow_reuse_address = True


class ForkingServer(SocketServer.ForkingMixIn, Server):

    def finish_request(self, request, client_address):
        Crypto.Random.atfork()
        return Server.finish_request(self, request, client_address)


class ThreadingServer(SocketServer.ThreadingMixIn, Server):
    pass


if __name__ == '__main__':
    # XXX
    logging.basicConfig(level=logging.INFO)
    server = Server(('localhost', 9999), None)
    server.serve_forever()
