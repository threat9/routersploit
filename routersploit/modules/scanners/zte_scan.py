from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Zte vulnerabilities.
    """
    __info__ = {
        'name': 'Zte Scanner',
        'description': 'Scanner module for Zte devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Zte',
        ),
    }
    modules = ['routers/zte', 'cameras/zte', 'misc/zte']
