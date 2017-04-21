from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Technicolor vulnerabilities.
    """
    __info__ = {
        'name': 'Technicolor Scanner',
        'description': 'Scanner module for Technicolor devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Technicolor',
        ),
    }
    modules = ['routers/technicolor', 'cameras/technicolor', 'misc/technicolor']
