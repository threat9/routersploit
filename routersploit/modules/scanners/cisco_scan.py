from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Cisco vulnerabilities.
    """
    __info__ = {
        'name': 'Cisco Scanner',
        'description': 'Scanner module for Cisco devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Cisco',
        ),
    }
    modules = ['routers/cisco', 'cameras/cisco', 'misc/cisco']
