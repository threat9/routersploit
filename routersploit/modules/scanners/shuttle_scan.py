from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Shuttle vulnerabilities.
    """
    __info__ = {
        'name': 'Shuttle Scanner',
        'description': 'Scanner module for Shuttle devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Shuttle',
        ),
    }
    modules = ['routers/shuttle', 'cameras/shuttle', 'misc/shuttle']
