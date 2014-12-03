from __future__ import unicode_literals


class SFTPProxyInterface(object):
    """SFTPProxyInterface is an interface for providing information about
    SFTP proxying and do file content manipulate.

    It should provides properties:

        - `address` the address of the upstream SFTP server
        - `config` the proxy configuration

    and some optional keys you can specify in `config`

        - `host_identity` the host identity you expected to see
        - `private_key` the private key key for authentication
        - `username` username for the upstream server
        - `password` password for the upstream server

    """

    def authenticate(self, key=None, password=None):
        """Authenticate user by given key or password

        """
        return False

    def ingress_handler(self, path, input_file, output_file):
        """Called to handle ingress file (written file), and return the
        modified file object. Path is the file path of written file, input_file
        is the written file. output_file is the file for outputting modified
        content

        """
        output_file.write(input_file.read())

    def egress_handler(self, path, input_file, output_file):
        """Called to handle egress file (read file), and return the
        modified file object. Path is the file path of read file, input_file
        is the read file. output_file is the file for outputting modified
        content
        
        """
        output_file.write(input_file.read())
