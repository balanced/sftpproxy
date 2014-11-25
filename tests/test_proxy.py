from __future__ import unicode_literals
import StringIO

import paramiko

from . import TestSFTPProxyBase


class TestOriginSFTPProxy(TestSFTPProxyBase):

    def test_basic_operations(self):
        password = 'foobar'
        user = self._register(
            root=self.fixture_path('dummy_files'),
            password=password,
        )
        t = paramiko.Transport(self.origin_server.server_address)
        t.connect(
            username=user.name,
            password=password,
        )
        self.cli = paramiko.SFTPClient.from_transport(t)
        self.assertEqual(
            set(self.cli.listdir()),
            set(['./eggs', './foo', './hello']),
        )
        self.assertEqual(self.cli.file('hello').read(), 'baby')
        self.assertEqual(self.cli.file('foo').read(), 'bar')
        self.assertEqual(self.cli.file('eggs').read(), 'spam')

        self.cli.remove('foo')
        self.assertEqual(
            set(self.cli.listdir()),
            set(['./eggs', './hello']),
        )

        self.cli.rename('eggs', 'spam')
        self.assertEqual(
            set(self.cli.listdir()),
            set(['./spam', './hello']),
        )

        self.cli.mkdir('yo')
        self.cli.putfo(StringIO.StringIO('up'), 'yo/whats')
        self.assertEqual(
            set(self.cli.listdir()),
            set(['./spam', './hello', './yo']),
        )
        self.assertEqual(
            set(self.cli.listdir('yo')),
            set(['yo/whats']),
        )
