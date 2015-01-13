from __future__ import unicode_literals


class DoNotPassThrough(Exception):
    """This exception indicates that do not pass the file through to upstream
    server.

    """


class SFTPProxyInterface(object):
    """SFTPProxyInterface is an interface for providing information about
    SFTP proxying and do file content manipulate.

    It should provides attributes:

        - `address` the address of the upstream SFTP server

    and some optional attributes:

        - `host_identity` the host identity you expected to see
        - `private_key` the private key key for authentication
        - `username` username for the upstream server
        - `password` password for the upstream server

    """

    def authenticate(self, password=None, key=None):
        """Authenticate user by given key or password. Return a boolean value
        to indicate whether user is authenticated

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

    def session_started(self, client_address):
        """Called to notify that the SFTP session is started. The address of
        client is passed as the first arguemtn in a format like
        
            ('127.0.0.1', 61126)

        """
        pass

    def session_ended(self):
        """Called to notify that the SFTP session is ended. This is a good
        place for doing some cleanup job like closing database session.

        """
        pass
