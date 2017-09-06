from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for cameras.
    """
    __info__ = {
        'name': 'Cameras Scanner',
        'description': 'Scanner module for cameras',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (),
        'devices': (),
    }
    modules = ['cameras']
