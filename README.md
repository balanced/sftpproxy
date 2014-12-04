sftpproxy
=========

[![Build Status](https://travis-ci.org/balanced/sftpproxy.svg?branch=master)](https://travis-ci.org/balanced/sftpproxy)

A SFTP proxy library

Example
=======

Here is a simple hodor SFTP proxy. It replaces world in the content of uploaded and downloaded files.

```python
from __future__ import unicode_literals
import os
import re
import logging

import paramiko
from sftpproxy import ThreadingTCPServer
from sftpproxy.interfaces import SFTPProxyInterface


class HodorProxy(SFTPProxyInterface):

    def __init__(self, username):
        self.username = username
        self.address = '127.0.0.1:2222'
        self.config = {
            'username': 'vagrant',
            'private_key': paramiko.RSAKey.from_private_key_file(
                os.path.expanduser('~/.vagrant.d/insecure_private_key')
            ),
        }

    def authenticate(self, *args, **kwargs):
        return True

    def ingress_handler(self, path, input_file, output_file):
        word_pattern = re.compile(r'(\w+)')
        data = word_pattern.sub('hodor', input_file.read())
        output_file.write(data)

    def egress_handler(self, path, input_file, output_file):
        word_pattern = re.compile(r'(\w+)')
        data = word_pattern.sub('hodor', input_file.read())
        output_file.write(data)


if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
    host_key = paramiko.RSAKey.from_private_key_file(sys.argv[1])
    server = ThreadingTCPServer(('localhost', 9999), host_key)
    server.config['SFTP_PROXY_FACTORY'] = HodorProxy
    server.serve_forever()
```

Run the server like this

```bash
python hodor_proxy.py ~/.ssh/id_rsa
```

then connect the SFT and put some files

```bash
$ sftp -P 9999 127.0.0.1
Connected to 127.0.0.1.
sftp> put setup.py
Uploading setup.py to /home/vagrant/setup.py
setup.py                                                                                        100% 2017     2.0KB/s   00:00    
sftp> 
```

Then you can see the uploaded file are placed with hodor language beautufily.

```python
hodor hodor hodor hodor
hodor hodor


hodor = (
    hodor
    .hodor(hodor".*hodor = '(.*?)'", hodor.hodor)
    .hodor(hodor('hodor/hodor.hodor').hodor())
    .hodor(hodor)
)
```
