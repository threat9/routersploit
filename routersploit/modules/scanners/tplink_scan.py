from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for TP-Link vulnerabilities.
    """
    __info__ = {
        'name': 'TP-Link Scanner',
        'description': 'Scanner module for Netgear devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'TP-Link',
        ),
    }
    modules = ['routers/tplink', 'cameras/tplink', 'misc/tplink']
