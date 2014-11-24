from __future__ import unicode_literals
import time
import logging
import functools
import threading
import SocketServer

import paramiko
import Crypto.Random

from .utils import as_sftp_error
from .file_handles import SFTPHandle
from .file_handles import SFTPWriteHandle

logger = logging.getLogger(__name__)

__version__ = '0.0.0'


class SFTPServerInterface(paramiko.SFTPServerInterface):

    def __init__(self, server, *args, **kwargs):
        self.client_address = server.client_address
        super(SFTPServerInterface, self).__init__(server, *args, **kwargs)

    # paramiko.SFTPServerInterface

    def session_started(self):
        # XXX
        return
        t = paramiko.Transport(self.proxy.config.address)
        t.connect(
            hostkey=self.proxy.config.host_identity,
            username=self.username,
            password=self.password,
            pkey=self.proxy.config.identity,
        )
        self.upstream = paramiko.SFTPClient.from_transport(t)

    def session_ended(self):
        # XXX
        return
        # NOTE: self.upstream.close() doesn't send disconnect msg
        if self.upstream is not None:
            self.upstream.sock.transport.close()
            self.upstream = None

    @as_sftp_error
    def open(self, path, flags, attr):
        mode = SFTPHandle.as_mode(flags)
        if mode in ('r',):
            # TODO:
            pass
        elif mode in ('w', 'w+'):
            return SFTPWriteHandle(
                owner=self,
                path=path,
                flags=flags,
                attr=attr,
            )
        return paramiko.sftp.SFTP_OP_UNSUPPORTED


class SSHServerInterface(paramiko.ServerInterface):

    def __init__(self, server, client_address):
        self.client_address = client_address
        self.proxy = None
        self.username = None
        self.password = None
        self.key = None

    def get_allowed_auths(self, username):
        auths = []
        auths.append('password')
        auths.append('publickey')
        return ','.join(auths)

    def check_auth_none(self, username):
        # XXX:
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        # XXX:
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        # XXX:
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        # XXX:
        return paramiko.OPEN_SUCCEEDED
    # TODO:


class SFTPRequestHandler(SocketServer.StreamRequestHandler):

    negotiation_poll = 0.1

    negotiation_timeout = 60

    auth_timeout = 60

    join_timeout = 10

    SFTPServer = SFTPServerInterface

    SSHServer = SSHServerInterface

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
            name='sftp',
            handler=paramiko.SFTPServer,
            sftp_si=self.SFTPServer,
        )

        try:
            # serve
            event = threading.Event()
            transport.start_server(
                event=event,
                server=self.SSHServer(self.server, client_address),
            )

            # negotiate
            start = time.time()
            while True:
                if event.wait(self.negotiation_poll):
                    if not transport.is_active():
                        ex = transport.get_exception() or 'Negotiation failed.'
                        logger.warning(
                            '%s, disconnecting - %s',
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
                        '%s, disconnecting - Negotiation timedout.',
                        self.client_address_str,
                    )
                    return

            # accepted
            channel = transport.accept(self.auth_timeout)
            if channel is None:
                logger.warning(
                    '%s, disconnecting - auth failed, channel is None.',
                    self.client_address_str,
                )
                return

            # command(s)
            while transport.isAlive():
                transport.join(timeout=self.join_timeout)
        finally:
            logger.info(
                '%s, cleaning up connection - Bye.',
                self.client_address_str,
            )
            transport.close()
        # TODO:


class TCPServer(SocketServer.TCPServer):

    def __init__(self, address, host_key):
        SocketServer.TCPServer.__init__(
            self,
            address,
            functools.partial(SFTPRequestHandler, host_key=host_key)
        )

    allow_reuse_address = True


class ForkingTCPServer(SocketServer.ForkingMixIn, TCPServer):

    def finish_request(self, request, client_address):
        Crypto.Random.atfork()
        return TCPServer.finish_request(self, request, client_address)


class ThreadingTCPServer(SocketServer.ThreadingMixIn, TCPServer):
    pass
