from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Ipfire vulnerabilities.
    """
    __info__ = {
        'name': 'Ipfire Scanner',
        'description': 'Scanner module for Ipfire devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Ipfire',
        ),
    }
    modules = ['routers/ipfire', 'cameras/ipfire', 'misc/ipfire']
