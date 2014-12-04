from __future__ import unicode_literals
import os
import tempfile
import StringIO

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


class SFTPWritingHandle(SFTPHandle):

    def __init__(self, owner, path, flags, attr):
        super(SFTPWritingHandle, self).__init__(owner, path, flags, attr)
        mode = self.as_mode(flags)
        if mode not in ('w', 'w+'):
            raise ValueError('Unsupported mode "{0}"'.format(mode))
        self.mode = mode
        self.normalized_path = path
        self.input_file = self._tmp()

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
        offset = self.input_file.tell()
        try:
            self.input_file.seek(0)
            output_file = StringIO.StringIO()
            self.owner.proxy.ingress_handler(
                path=self.path,
                input_file=self.input_file,
                output_file=output_file,
            )
            output_file.seek(0)
            # flush the modified file to upstream
            self.owner.upstream.putfo(output_file, self.path)
        finally:
            self.input_file.seek(offset)

    # paramiko.SFTPHandle

    @as_sftp_error
    def close(self):
        self._modify_pass_through()
        self.input_file.close()
        return paramiko.SFTP_OK

    @as_sftp_error
    def write(self, offset, data):
        self.input_file.seek(offset)
        self.input_file.write(data)
        return paramiko.SFTP_OK

    @as_sftp_error
    def stat(self):
        return self.input_file.stat()


class SFTPReadingHandle(SFTPHandle):

    def __init__(self, owner, path, flags, attr):
        super(SFTPReadingHandle, self).__init__(owner, path, flags, attr)
        mode = self.as_mode(flags)
        if mode not in ('r',):
            raise ValueError('Unsupported mode "{0}"'.format(mode))
        self.mode = mode
        self.normalized_path = self.normalize(path)
        self.output_file = self._modify_read_file(self._input_file())

    def _input_file(self):
        fo = StringIO.StringIO()
        self.owner.upstream.getfo(self.path, fo)
        fo.seek(0)
        return fo

    def _modify_read_file(self, input_file):
        fd, tmp_path = tempfile.mkstemp()
        output_file = os.fdopen(fd, 'r+')
        self.owner.proxy.egress_handler(
            path=self.normalized_path,
            input_file=input_file,
            output_file=output_file,
        )
        output_file.seek(0)
        stat = self.owner.upstream.stat(self.path)
        os.utime(tmp_path, (stat.st_atime or 0, stat.st_mtime or 0))
        return output_file

    # paramiko.SFTPHandle

    @as_sftp_error
    def close(self):
        self.output_file.close()
        return paramiko.SFTP_OK

    @as_sftp_error
    def read(self, offset, length):
        self.output_file.seek(offset)
        data = self.output_file.read(length)
        return data

    @as_sftp_error
    def stat(self):
        return paramiko.SFTPAttributes.from_stat(
            os.fstat(self.output_file.fileno()), self.path
        )
