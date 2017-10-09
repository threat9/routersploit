from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Multi vulnerabilities.
    """
    __info__ = {
        'name': 'Multi Scanner',
        'description': 'Scanner module for Multi devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Multi',
        ),
    }
    modules = ['routers/multi', 'cameras/multi', 'misc/multi']
