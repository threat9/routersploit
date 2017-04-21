from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Zyxel vulnerabilities.
    """
    __info__ = {
        'name': 'Zyxel Scanner',
        'description': 'Scanner module for Zyxel devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Zyxel',
        ),
    }
    modules = ['routers/zyxel', 'cameras/zyxel', 'misc/zyxel']
