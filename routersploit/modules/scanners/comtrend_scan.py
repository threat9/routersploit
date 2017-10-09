from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Comtrend vulnerabilities.
    """
    __info__ = {
        'name': 'Comtrend Scanner',
        'description': 'Scanner module for Comtrend devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Comtrend',
        ),
    }
    modules = ['routers/comtrend', 'cameras/comtrend', 'misc/comtrend']
