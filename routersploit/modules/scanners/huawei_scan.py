from __future__ import absolute_import

from .autopwn import Exploit as BaseScanner


class Exploit(BaseScanner):
    """
    Scanner implementation for Huawei vulnerabilities.
    """
    __info__ = {
        'name': 'Huawei Scanner',
        'description': 'Scanner module for Huawei devices',
        'authors': [
            'Mariusz Kupidura <f4wkes[at]gmail.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Huawei',
        ),
    }
    modules = ['routers/huawei', 'cameras/huawei', 'misc/huawei']
