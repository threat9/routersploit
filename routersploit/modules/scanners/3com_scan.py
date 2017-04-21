from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for 3com vulnerabilities.
    """
    __info__ = {
        'name': '3com Scanner',
        'description': 'Scanner module for 3com devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            '3com',
        ),
    }
    modules = ['routers/3com', 'cameras/3com', 'misc/3com']
