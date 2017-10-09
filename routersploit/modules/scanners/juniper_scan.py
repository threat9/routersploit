from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Juniper vulnerabilities.
    """
    __info__ = {
        'name': 'Juniper Scanner',
        'description': 'Scanner module for Juniper devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Juniper',
        ),
    }
    modules = ['routers/juniper', 'cameras/juniper', 'misc/juniper']
