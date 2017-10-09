from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Dlink vulnerabilities.
    """
    __info__ = {
        'name': 'Dlink Scanner',
        'description': 'Scanner module for Dlink devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Dlink',
        ),
    }
    modules = ['routers/dlink', 'cameras/dlink', 'misc/dlink']
