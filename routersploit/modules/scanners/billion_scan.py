from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Billion vulnerabilities.
    """
    __info__ = {
        'name': 'Billion Scanner',
        'description': 'Scanner module for Billion devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Billion',
        ),
    }
    modules = ['routers/billion', 'cameras/billion', 'misc/billion']
