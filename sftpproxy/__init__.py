from __future__ import unicode_literals
import functools
import SocketServer

import Crypto.Random

__version__ = '0.0.0'


class SFTPRequestHandler(SocketServer.StreamRequestHandler):
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

    def handle(self):
        # TODO:
        print 'Connection made', self.request
        pass


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
    server = Server(('localhost', 9999), None)
    server.serve_forever()
