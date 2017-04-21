from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):

    """Scanner implementation for BHU vulnerabilities."""

    __info__ = {
        'name': 'BHU Scanner',
        'description': 'Scanner module for BHU devices',
        'authors': [
            'Tao "depierre" Sauvage',
        ],
        'references': (
            '',
        ),
        'devices': (
            'BHU uRouter',
        ),
    }
    modules = ['routers/bhu', 'cameras/bhu', 'misc/bhu']
