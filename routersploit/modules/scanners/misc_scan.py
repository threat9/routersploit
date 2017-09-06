from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for misc devices.
    """
    __info__ = {
        'name': 'Misc Scanner',
        'description': 'Scanner module for misc devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (),
        'devices': (),
    }
    modules = ['misc']
