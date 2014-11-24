from __future__ import unicode_literals
import logging
import functools

import paramiko


logger = logging.getLogger(__name__)


def as_sftp_error(func):
    """Decorates a function for outgoing SFTP operations, try to catch its
    exceptions and convert them into error number and return

    """

    name = getattr(func, 'func_name', '<unknown>')

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.debug(
            '%s - enter on (%r,%r) from %s',
            name, args[1:], kwargs, args[0].client_address,
        )
        try:
            rc = func(*args, **kwargs)
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as ex:
            if hasattr(ex, 'errno'):
                error = ex.errno
            else:
                error = None
            rc = paramiko.SFTPServer.convert_errno(error)
            logger.exception(
                '%s - error %s on (%r%r) from %s\n',
                name, rc, args[1:], kwargs, args[0].client_address,
            )
        logger.debug(
            '%s - exit %s',
            name, '<data>' if isinstance(rc, basestring) else rc
        )
        return rc

    return wrapper
