from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Netgear vulnerabilities.
    """
    __info__ = {
        'name': 'Netgear Scanner',
        'description': 'Scanner module for Netgear devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Netgear',
        ),
    }
    modules = ['routers/netgear', 'cameras/netgear', 'misc/netgear']
