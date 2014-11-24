from __future__ import unicode_literals
import os
import tempfile

import paramiko

from .utils import as_sftp_error


class SFTPHandle(paramiko.SFTPHandle):
    """Base SFTP file handle

    """

    @classmethod
    def as_mode(cls, flags):
        open_flag = flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)
        if open_flag == os.O_RDONLY:
            mode = 'r'
        elif open_flag == os.O_WRONLY:
            mode = 'w'
        elif open_flag == os.O_RDWR:
            mode = 'rw'
        if flags & os.O_APPEND:
            mode += '+'
        return mode

    def __init__(self, owner, path, flags, attr):
        super(SFTPHandle, self).__init__(flags)
        self.owner = owner
        self.path = path

    @property
    def client_address(self):
        return self.owner.client_address

    def normalize(self, path):
        path = self.owner.upstream.normalize(path)
        if path.startswith('//'):
            path = path[1:]
        return path


class SFTPWriteHandle(SFTPHandle):

    def __init__(self, owner, path, flags, attr):
        super(SFTPWriteHandle, self).__init__(owner, path, flags, attr)
        mode = self.as_mode(flags)
        if mode not in ('w', 'w+'):
            raise ValueError('Unsupported mode "{0}"'.format(mode))
        self.mode = mode
        self.normalized_path = path
        self.temp_file = self._tmp()

    def _tmp(self):
        """Create a temporary file for written data and return

        """
        fd, tmp_path = tempfile.mkstemp()
        fo = os.fdopen(fd, 'w+')
        return fo

    def _modify_pass_through(self):
        """Call ingress handler of proxy to modify the file and pass through
        to upstream server

        """
        offset = self.temp_file.tell()
        try:
            self.temp_file.seek(0)
            modified_file = self.owner.proxy.ingress_handler(
                path=self.path,
                fileobj=self.temp_file,
            )
        finally:
            self.temp_file.seek(offset)
        # XXX: WTF?
        # db.Session.rollback()  # NOTE: release transaction resources
        modified_file.seek(0)
        # flush the modified file to upstream
        self.owner.upstream.putfo(modified_file, self.path)

    # paramiko.SFTPHandle

    @as_sftp_error
    def close(self):
        self._modify_pass_through()
        self.temp_file.close()
        return paramiko.SFTP_OK

    @as_sftp_error
    def write(self, offset, data):
        self.temp_file.seek(offset)
        self.temp_file.write(data)
        return paramiko.SFTP_OK

    @as_sftp_error
    def stat(self):
        return self.temp_file.stat()
