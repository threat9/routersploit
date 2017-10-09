from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Netcore vulnerabilities.
    """
    __info__ = {
        'name': 'Netcore Scanner',
        'description': 'Scanner module for Netcore devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Netcore',
        ),
    }
    modules = ['routers/netcore', 'cameras/netcore', 'misc/netcore']
