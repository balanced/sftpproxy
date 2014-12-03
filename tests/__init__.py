from __future__ import unicode_literals
import unittest
import collections
import functools
import os
import shutil
import SocketServer
import StringIO
import tempfile
import threading
import uuid
import logging

import paramiko

from sftpproxy import ThreadingTCPServer
from sftpproxy import SFTPStreamRequestHandler
from sftpproxy.file_handles import SFTPHandle
from sftpproxy.utils import as_sftp_error

logger = logging.getLogger(__name__)


class Handle(SFTPHandle):

    def __init__(self, owner, path, flags, attr):
        super(Handle, self).__init__(owner, path, flags, attr)
        mode = self.as_mode(flags)
        self.mode = mode
        self.fo = open(
            os.path.normpath(self.owner.normalize(path)), self.mode,
        )

    # paramiko.SFTPHandle

    @as_sftp_error
    def close(self):
        self.fo.close()
        return paramiko.SFTP_OK

    @as_sftp_error
    def read(self, offset, length):
        self.fo.seek(offset)
        data = self.fo.read(length)
        return data

    @as_sftp_error
    def write(self, offset, data):
        self.fo.seek(offset)
        self.fo.write(data)
        return paramiko.SFTP_OK

    @as_sftp_error
    def stat(self):
        return paramiko.SFTPAttributes.from_stat(
            os.fstat(self.fo.fileno()), self.path
        )


class SFTPServerHandler(paramiko.SFTPServerInterface):

    def __init__(self, ssh_server, *args, **kwargs):
        self.client_address = ssh_server.client_address
        self.user = ssh_server.authenticated_user
        paramiko.SFTPServerInterface.__init__(
            self, ssh_server, *args, **kwargs
        )

    def normalize(self, path):
        return os.path.normpath(
            self.user.root + os.path.realpath(os.path.normpath('/' + path))
        )

    # paramiko.SFTPServerInterface

    @as_sftp_error
    def open(self, path, flags, attr):
        return Handle(self, path, flags, attr)

    @as_sftp_error
    def list_folder(self, path):
        return [
            self.stat(os.path.join(path, v))
            for v in os.listdir(self.normalize(path))
        ]

    @as_sftp_error
    def stat(self, path):
        return paramiko.SFTPAttributes.from_stat(
            os.stat(self.normalize(path)), path
        )

    @as_sftp_error
    def lstat(self, path):
        return self.stat(path)

    @as_sftp_error
    def remove(self, path):
        os.remove(self.normalize(path))
        return paramiko.SFTP_OK

    @as_sftp_error
    def rename(self, oldpath, newpath):
        os.rename(self.normalize(oldpath), self.normalize(newpath))
        return paramiko.SFTP_OK

    @as_sftp_error
    def mkdir(self, path, attr):
        os.mkdir(self.normalize(path), attr.st_mode)
        return paramiko.SFTP_OK

    @as_sftp_error
    def rmdir(self, path):
        os.rmdir(self.normalize(path))
        return paramiko.SFTP_OK

    @as_sftp_error
    def canonicalize(self, path):
        return os.path.realpath(os.path.normpath(b'/' + path))


class SSHServerHandler(paramiko.ServerInterface):

    def __init__(self, server, client_address):
        self.users = server.users
        self.authenticated_user = None
        self.client_address = client_address

    # paramiko.ServerInterface

    def get_allowed_auths(self, username):
        auths = []
        user = self.users.get(username)
        if user and user.password is not None:
            auths.append('password')
        if user and user.rsa_key:
            auths.append('publickey')
        return ','.join(auths)

    def check_auth_none(self, username):
        user = self.users.get(username)
        if user and user.password is None and user.rsa_key is None:
            self.authenticated_user = user
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        user = self.users.get(username)
        if user and user.password == password:
            self.authenticated_user = user
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        user = self.users.get(username)
        if user and user.rsa_key == key:
            self.authenticated_user = user
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED


class SFTPOrigin(
    SocketServer.TCPServer,
    SocketServer.ThreadingMixIn,
):
    
    User = collections.namedtuple('User', ['name', 'password', 'rsa_key', 'root'])

    def __init__(self, address, host_key):
        self.users = {}
        SocketServer.TCPServer.__init__(
            self,
            address,
            functools.partial(
                SFTPStreamRequestHandler,
                host_key=host_key,
                ssh_handler_factory=SSHServerHandler,
                sftp_handler_factory=SFTPServerHandler,
            ),
        )
        self.config = {}


class TestSFTPProxyBase(unittest.TestCase):

    origin_server = None

    @classmethod
    def setUpClass(cls):
        super(TestSFTPProxyBase, cls).setUpClass()

        # origin server
        cls.origin_server = SFTPOrigin(
            address=('localhost', 0),
            host_key=paramiko.RSAKey.from_private_key_file(
                cls.fixture_path('sftp', 'origin_rsa')
            ),
        )
        origin_thread = threading.Thread(target=cls.origin_server.serve_forever)
        origin_thread.daemon = True
        origin_thread.start()

        # proxy server
        cls.proxy_server = ThreadingTCPServer(
            address=('localhost', 0),
            host_key=paramiko.RSAKey.from_private_key_file(
                cls.fixture_path('sftp', 'proxy_rsa')
            ),
        )
        proxy_thread = threading.Thread(target=cls.proxy_server.serve_forever)
        proxy_thread.daemon = True
        proxy_thread.start()

    def _register(self, root, password=None, rsa_key=None):
        """Register a user in origin server with given root folder to copy
        files from

        """

        def ignore(src, names):
            return filter(lambda x: 'ignore' in x, names)

        tmp_path = tempfile.mktemp(prefix='sftpproxy-test-')
        shutil.copytree(root, tmp_path, ignore=ignore)
        user = SFTPOrigin.User(
            name='US' + uuid.uuid4().hex,
            password=password,
            rsa_key=(
                paramiko.RSAKey.from_private_key(StringIO.StringIO(rsa_key))
                if rsa_key
                else None
            ),
            root=tmp_path,
        )
        self.origin_server.users[user.name] = user
        self.addCleanup(functools.partial(self._unregister, user.name))
        return user

    def _unregister(self, username):
        user = self.origin_server.users[username]
        del self.origin_server.users[username]
        shutil.rmtree(user.root)

    @classmethod
    def fixture_path(cls, *parts):
        base_path = os.path.dirname(__file__)
        return os.path.join(base_path, 'fixtures', *parts)

    @classmethod
    def open_fixture(cls, *path):
        return open(cls.fixture_path(*path), 'r')

    @classmethod
    def read_fixture(cls, *path):
        return cls.open_fixture(*path).read()
