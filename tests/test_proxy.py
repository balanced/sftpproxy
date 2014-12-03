from __future__ import unicode_literals
import StringIO

import paramiko

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

        def make_proxy(username):
            proxy = SFTPProxyInterface()
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
