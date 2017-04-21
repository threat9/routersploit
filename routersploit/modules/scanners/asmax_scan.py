from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Asmax vulnerabilities.
    """
    __info__ = {
        'name': 'Asmax Scanner',
        'description': 'Scanner module for Asmax devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Asmax',
        ),
    }
    modules = ['routers/asmax', 'cameras/asmax', 'misc/asmax']
