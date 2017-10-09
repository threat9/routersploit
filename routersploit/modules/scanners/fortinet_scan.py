from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Fortinet vulnerabilities.
    """
    __info__ = {
        'name': 'Fortinet Scanner',
        'description': 'Scanner module for Fortinet devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Fortinet',
        ),
    }
    modules = ['routers/fortinet', 'cameras/fortinet', 'misc/fortinet']
