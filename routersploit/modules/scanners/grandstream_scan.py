from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Grandstream vulnerabilities.
    """
    __info__ = {
        'name': 'Grandstream Scanner',
        'description': 'Scanner module for Grandstream devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Grandstream',
        ),
    }
    modules = ['routers/grandstream', 'cameras/grandstream', 'misc/grandstream']
