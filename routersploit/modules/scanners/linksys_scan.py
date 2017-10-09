from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Linksys vulnerabilities.
    """
    __info__ = {
        'name': 'Linksys Scanner',
        'description': 'Scanner module for Linksys devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Linksys',
        ),
    }
    modules = ['routers/linksys', 'cameras/linksys', 'misc/linksys']
