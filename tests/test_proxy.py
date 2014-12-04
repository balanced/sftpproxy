from __future__ import unicode_literals
import os
import re
import StringIO

import paramiko
from paramiko.ssh_exception import AuthenticationException
from paramiko.ssh_exception import ChannelException

from sftpproxy.interfaces import SFTPProxyInterface
from . import TestSFTPProxyBase


class TestSFTPProxy(TestSFTPProxyBase):

    def _test_basic_operations(self, cli):
        self.assertEqual(
            set(cli.listdir()),
            set(['./eggs', './foo', './hello']),
        )
        self.assertEqual(cli.file('hello').read(), 'baby')
        self.assertEqual(cli.file('foo').read(), 'bar')
        self.assertEqual(cli.file('eggs').read(), 'spam')

        cli.remove('foo')
        self.assertEqual(
            set(cli.listdir()),
            set(['./eggs', './hello']),
        )

        cli.rename('eggs', 'spam')
        self.assertEqual(
            set(cli.listdir()),
            set(['./spam', './hello']),
        )

        cli.mkdir('yo')
        cli.putfo(StringIO.StringIO('up'), 'yo/whats')
        self.assertEqual(
            set(cli.listdir()),
            set(['./spam', './hello', './yo']),
        )
        self.assertEqual(
            set(cli.listdir('yo')),
            set(['yo/whats']),
        )
        # TODO: add reading test

    def _make_transport(self, *args, **kwargs):
        """Make a transport that will always be closed after tearDown,
        otherwise the connection will be blocked

        """
        transport = paramiko.Transport(*args, **kwargs)
        self.addCleanup(transport.close)
        return transport

    def test_origin_basic_operations(self):
        password = 'foobar'
        user = self._register(
            root=self.fixture_path('dummy_files'),
            password=password,
        )
        transport = self._make_transport(self.origin_server.server_address)
        transport.connect(
            username=user.name,
            password=password,
        )
        cli = paramiko.SFTPClient.from_transport(transport)
        self._test_basic_operations(cli)

    def test_basic_operations(self):

        class AuthFreeProxy(SFTPProxyInterface):
            def authenticate(self, *args, **kwargs):
                return True

        def make_proxy(username):
            proxy = AuthFreeProxy()
            proxy.address = ':'.join(map(str, self.origin_server.server_address))
            proxy.config = dict(
                username=user.name,
                password=password,
            )
            return proxy

        self.proxy_server.config['SFTP_PROXY_FACTORY'] = make_proxy

        password = 'foobar'
        user = self._register(
            root=self.fixture_path('dummy_files'),
            password=password,
        )
        transport = self._make_transport(self.proxy_server.server_address)
        transport.connect(
            username=user.name,
            password=password,
        )
        cli = paramiko.SFTPClient.from_transport(transport)

        self._test_basic_operations(cli)

    def test_auth_failed(self):
        auth_calls = []

        class AuthRejectProxy(SFTPProxyInterface):
            def authenticate(self, *args, **kwargs):
                auth_calls.append((args, kwargs))
                return False

        def make_proxy(username):
            proxy = AuthRejectProxy()
            proxy.address = ':'.join(map(str, self.origin_server.server_address))
            proxy.config = dict(
                username=user.name,
                password=password,
            )
            return proxy

        self.proxy_server.config['SFTP_PROXY_FACTORY'] = make_proxy

        password = 'foobar'
        user = self._register(
            root=self.fixture_path('dummy_files'),
            password=password,
        )

        with self.assertRaises(AuthenticationException):
            transport = self._make_transport(self.proxy_server.server_address)
            transport.connect(
                username=user.name,
                pkey=paramiko.RSAKey.from_private_key_file(
                    self.fixture_path('sftp', 'proxy_rsa')
                ),
            )

        with self.assertRaises(AuthenticationException):
            transport = self._make_transport(self.proxy_server.server_address)
            transport.connect(
                username=user.name,
                password=password,
            )

        with self.assertRaises(ChannelException):
            transport = self._make_transport(self.proxy_server.server_address)
            transport.connect(username=user.name)
            cli = paramiko.SFTPClient.from_transport(transport)
            cli.listdir()

        self.assertEqual(len(auth_calls), 2)
        self.assertEqual(auth_calls[1], (tuple(), dict(password=password)))

        expected_pub_key = self.read_fixture('sftp', 'proxy_rsa.pub').split()[1]
        pub_key = auth_calls[0][1]['key']
        self.assertEqual(pub_key.get_base64(), expected_pub_key)

    def test_ingress_hodor_proxy(self):

        class HodorProxy(SFTPProxyInterface):
            def authenticate(self, *args, **kwargs):
                return True

            def ingress_handler(self, path, input_file, output_file):
                data = input_file.read()
                word_pattern = re.compile(r'(\w+)')
                data = word_pattern.sub('hodor', data)
                output_file.write(data)

        def make_proxy(username):
            proxy = HodorProxy()
            proxy.address = ':'.join(map(str, self.origin_server.server_address))
            proxy.config = dict(
                username=user.name,
                password=password,
            )
            return proxy

        self.proxy_server.config['SFTP_PROXY_FACTORY'] = make_proxy

        password = 'foobar'
        user = self._register(
            root=self.fixture_path('dummy_files'),
            password=password,
        )
        transport = self._make_transport(self.proxy_server.server_address)
        transport.connect(
            username=user.name,
            password=password,
        )
        cli = paramiko.SFTPClient.from_transport(transport)
        cli.putfo(
            StringIO.StringIO('a quick fox jump over the lazy dog'),
            'hodor',
            confirm=False,
        )

        hodor_path = os.path.join(user.root, 'hodor')
        with open(hodor_path, 'rt') as result_file:
            self.assertEqual(
                result_file.read(),
                'hodor hodor hodor hodor hodor hodor hodor hodor',
            )
