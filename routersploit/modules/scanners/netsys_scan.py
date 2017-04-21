from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Netsys vulnerabilities.
    """
    __info__ = {
        'name': 'Netsys Scanner',
        'description': 'Scanner module for Netsys devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Netsys',
        ),
    }
    modules = ['routers/netsys', 'cameras/netsys', 'misc/netsys']
