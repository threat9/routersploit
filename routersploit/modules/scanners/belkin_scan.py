from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Belkin vulnerabilities.
    """
    __info__ = {
        'name': 'Belkin Scanner',
        'description': 'Scanner module for Belkin devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Belkin',
        ),
    }
    modules = ['routers/belkin', 'cameras/belkin', 'misc/belkin']
