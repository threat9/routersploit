from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for routers.
    """
    __info__ = {
        'name': 'Router Scanner',
        'description': 'Scanner module for routers',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (),
        'devices': (),
    }
    modules = ['routers']
