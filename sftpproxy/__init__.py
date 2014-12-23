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
from .file_handles import SFTPReadingHandle
from .file_handles import SFTPWritingHandle

logger = logging.getLogger(__name__)

__version__ = '0.2.2'


class SFTPClient(paramiko.SFTPClient):
    def close(self):
        super(SFTPClient, self).close()
        # Notice: self.upstream.close() doesn't send disconnect msg
        self.sock.transport.close()


def make_default_sftp_client(
    address,
    host_identity,
    username,
    password,
    private_key,
):
    """Make a SFTP client

    """
    transport = paramiko.Transport(address)
    transport.connect(
        hostkey=host_identity,
        username=username,
        password=password,
        pkey=private_key,
    )
    return SFTPClient.from_transport(transport)


class SFTPServerHandler(paramiko.SFTPServerInterface):

    def __init__(self, server, *args, **kwargs):
        # the server is SSHServerInterface here
        self.client_address = server.client_address
        self.ssh_server = server
        self.proxy = server.proxy
        self.username = getattr(self.proxy, 'username', server.username)
        self.password = getattr(self.proxy, 'password', server.password)
        self.private_key = getattr(self.proxy, 'private_key', None)
        self.host_identity = getattr(self.proxy, 'host_identity', None)
        self.upstream_factory = getattr(
            self.proxy,
            'make_sftp_client',
            make_default_sftp_client,
        )
        self.upstream = None
        super(SFTPServerHandler, self).__init__(server, *args, **kwargs)

    # paramiko.SFTPServerInterface

    def session_started(self):
        self.upstream = self.upstream_factory(
            address=self.proxy.address,
            host_identity=self.host_identity,
            username=self.username,
            password=self.password,
            private_key=self.private_key,
        )

    def session_ended(self):
        try:
            self.proxy.session_ended()
        finally:
            if self.upstream is not None:
                self.upstream.close()
                self.upstream = None

    @as_sftp_error
    def open(self, path, flags, attr):
        mode = SFTPHandle.as_mode(flags)
        if mode in ('r',):
            return SFTPReadingHandle(
                owner=self,
                path=path,
                flags=flags,
                attr=attr,
            )
        elif mode in ('w', 'w+'):
            return SFTPWritingHandle(
                owner=self,
                path=path,
                flags=flags,
                attr=attr,
            )
        return paramiko.sftp.SFTP_OP_UNSUPPORTED

    @as_sftp_error
    def list_folder(self, path):
        return self.upstream.listdir_attr(path)

    @as_sftp_error
    def stat(self, path):
        return self.upstream.stat(path)

    @as_sftp_error
    def lstat(self, path):
        return self.stat(path)

    @as_sftp_error
    def remove(self, path):
        self.upstream.remove(path)
        return paramiko.SFTP_OK

    @as_sftp_error
    def rename(self, oldpath, newpath):
        self.upstream.rename(oldpath, newpath)
        return paramiko.SFTP_OK

    @as_sftp_error
    def mkdir(self, path, attr):
        self.upstream.mkdir(path)
        return paramiko.SFTP_OK

    @as_sftp_error
    def rmdir(self, path):
        self.upstream.rmdir(path)
        return paramiko.SFTP_OK

    @as_sftp_error
    def canonicalize(self, path):
        return self.upstream.normalize(path)


class SSHServerHandler(paramiko.ServerInterface):

    def __init__(self, server, client_address):
        # the server is TCPServer here
        self.client_address = client_address
        self.proxy = None
        self.username = None
        self.password = None
        self.key = None
        self.tcp_server = server
        # the sftp proxy factory
        self._proxy_factory = self.tcp_server.config['SFTP_PROXY_FACTORY']

    def get_allowed_auths(self, username):
        auths = []
        proxy = self._proxy_factory(username)
        if proxy is not None:
            auths.append('none')
            auths.append('password')
            auths.append('publickey')
        return ','.join(auths)

    def check_auth_none(self, username):
        proxy = self._proxy_factory(username)
        if proxy is not None and proxy.authenticate():
            self.proxy = proxy
            self.username = username
            logger.info(
                'auth none from %s succeeded, username=%s ',
                self.client_address, username,
            )
            return paramiko.AUTH_SUCCESSFUL
        logger.info(
            'auth none from %s failed, username=%s ',
            self.client_address, username,
        )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        proxy = self._proxy_factory(username)
        if proxy is not None and proxy.authenticate(key=key):
            self.proxy = proxy
            self.username = username
            self.key = key
            logger.info(
                'auth publickey from %s succeeded, username=%s ',
                self.client_address, username,
            )
            return paramiko.AUTH_SUCCESSFUL
        logger.info(
            'auth publickey from %s failed, username=%s ',
            self.client_address, username,
        )
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        proxy = self._proxy_factory(username)
        if proxy is not None and proxy.authenticate(password=password):
            self.proxy = proxy
            self.username = username
            self.password = password
            logger.info(
                'auth password from %s succeeded, username=%s ',
                self.client_address, username,
            )
            return paramiko.AUTH_SUCCESSFUL
        logger.info(
            'auth password from %s failed, username=%s ',
            self.client_address, username,
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session' and self.proxy is not None:
            return paramiko.OPEN_SUCCEEDED
        logger.info(
            'channel request denied from %s, kind=%s',
            self.client_address, kind
        )
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SFTPStreamRequestHandler(SocketServer.StreamRequestHandler):

    default_negotiation_poll = 0.1

    default_negotiation_timeout = 60

    default_auth_timeout = 60

    default_join_timeout = 10

    def __init__(
        self,
        request,
        client_address,
        server,
        host_key,
        ssh_handler_factory=SSHServerHandler,
        sftp_handler_factory=SFTPServerHandler,
    ):
        self.host_key = host_key
        self.ssh_handler_factory = ssh_handler_factory
        self.sftp_handler_factory = sftp_handler_factory
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

        negotiation_poll = self.server.config.get(
            'SFTP_PROXY_NEGOTIATION_POLL',
            self.default_negotiation_poll,
        )
        negotiation_timeout = self.server.config.get(
            'SFTP_PROXY_NEGOTIATION_TIMEOUT',
            self.default_negotiation_timeout,
        )
        auth_timeout = self.server.config.get(
            'SFTP_PROXY_AUTH_TIMEOUT',
            self.default_auth_timeout,
        )
        join_timeout = self.server.config.get(
            'SFTP_PROXY_JOIN_TIMEOUT',
            self.default_join_timeout,
        )

        # transport
        transport = paramiko.Transport(self.request)
        if self.host_key is not None:
            transport.add_server_key(self.host_key)
        transport.set_subsystem_handler(
            name='sftp',
            handler=paramiko.SFTPServer,
            sftp_si=self.sftp_handler_factory,
        )

        try:
            # serve
            event = threading.Event()
            transport.start_server(
                event=event,
                server=self.ssh_handler_factory(self.server, client_address),
            )

            # negotiate
            start = time.time()
            while True:
                if event.wait(negotiation_poll):
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
                    negotiation_timeout is not None and
                    time.time() - start > negotiation_timeout
                ):
                    logger.warning(
                        '%s, disconnecting - Negotiation timedout.',
                        self.client_address_str,
                    )
                    return

            # accepted
            channel = transport.accept(auth_timeout)
            if channel is None:
                logger.warning(
                    '%s, disconnecting - auth failed, channel is None.',
                    self.client_address_str,
                )
                return

            # command(s)
            while transport.isAlive():
                transport.join(timeout=join_timeout)
        finally:
            logger.info(
                '%s, cleaning up connection - Bye.',
                self.client_address_str,
            )
            transport.close()


class TCPServer(SocketServer.TCPServer):

    def __init__(self, address, host_key, config=None):
        SocketServer.TCPServer.__init__(
            self,
            address,
            functools.partial(SFTPStreamRequestHandler, host_key=host_key)
        )
        self.config = config or {}

    allow_reuse_address = True


class ForkingTCPServer(SocketServer.ForkingMixIn, TCPServer):

    def finish_request(self, request, client_address):
        Crypto.Random.atfork()
        return TCPServer.finish_request(self, request, client_address)


class ThreadingTCPServer(SocketServer.ThreadingMixIn, TCPServer):
    pass
