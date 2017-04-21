from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Asus vulnerabilities.
    """
    __info__ = {
        'name': 'Asus Scanner',
        'description': 'Scanner module for Asus devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Asus',
        ),
    }
    modules = ['routers/asus', 'cameras/asus', 'misc/asus']
