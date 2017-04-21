from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Thomson vulnerabilities.
    """
    __info__ = {
        'name': 'Thomson Scanner',
        'description': 'Scanner module for Thomson devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Thomson',
        ),
    }
    modules = ['routers/thomson', 'cameras/thomson', 'misc/thomson']
