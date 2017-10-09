from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Movistar vulnerabilities.
    """
    __info__ = {
        'name': 'Movistar Scanner',
        'description': 'Scanner module for Movistar devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Movistar',
        ),
    }
    modules = ['routers/movistar', 'cameras/movistar', 'misc/movistar']
