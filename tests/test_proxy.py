from __future__ import unicode_literals
import paramiko

from . import TestSFTPProxyBase


class TestSFTPProxy(TestSFTPProxyBase):

    def test_foobar(self):
        user = self._register(
            root='.',
            password='foobar',
        )
        t = paramiko.Transport(self.origin_server.server_address)
        t.connect(
            username=user.name,
            password='foobar',
        )
        self.cli = paramiko.SFTPClient.from_transport(t)
        print self.cli.listdir()
