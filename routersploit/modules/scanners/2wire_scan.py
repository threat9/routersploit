from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for 2wire vulnerabilities.
    """
    __info__ = {
        'name': '2wire Scanner',
        'description': 'Scanner module for 2wire devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            '2wire',
        ),
    }
    modules = ['routers/2wire', 'cameras/2wire', 'misc/2wire']
