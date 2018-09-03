import socket
import paramiko
import os
import select
import sys
import threading
import io

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_success
from routersploit.core.exploit.printer import print_error
from routersploit.core.exploit.utils import random_text


SSH_TIMEOUT = 8.0


class SSHCli(object):
    def __init__(self, ssh_target, ssh_port, verbosity):
        self.ssh_target = ssh_target
        self.ssh_port = ssh_port
        self.verbosity = verbosity

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def login(self, username, password, retries=1):
        for _ in range(retries):
            try:
                self.ssh_client.connect(self.ssh_target, self.ssh_port, timeout=SSH_TIMEOUT, banner_timeout=SSH_TIMEOUT, username=username, password=password, look_for_keys=False)
            except paramiko.AuthenticationException:
                print_error("SSH Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                self.ssh_client.close()
                break
            except Exception as err:
                print_error("Err: {}".format(err), verbose=self.verbosity)
            else:
                print_success("SSH Authentication Successful - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                return self.ssh_client

            self.ssh_client.close()

        return None

    def login_pkey(self, username, priv_key, retries=1):
        if "DSA PRIVATE KEY" in priv_key:
            priv_key = paramiko.DSSKey.from_private_key(io.StringIO(priv_key))
        elif "RSA PRIVATE KEY" in priv_key:
            priv_key = paramiko.RSAKey.from_private_key(io.StringIO(priv_key))
        else:
            return None

        for _ in range(retries):
            try:
                self.ssh_client.connect(self.ssh_target, self.ssh_port, timeout=SSH_TIMEOUT, banner_timeout=SSH_TIMEOUT, username=username, pkey=priv_key, look_for_keys=False)
            except paramiko.AuthenticationException:
                print_error("Authentication Failed - Username: '{}' auth with private key".format(username), verbose=self.verbosity)
            except Exception as err:
                print_error("Err: {}".format(err), verbose=self.verbosity)
            else:
                print_success("SSH Authentication Successful - Username: '{}' with private key".format(username), verbose=self.verbosity)
                return self.ssh_client

            self.ssh_client.close()

        return None

    def test_connect(self):
        try:
            self.ssh_client.connect(self.ssh_target, self.ssh_port, timeout=SSH_TIMEOUT, username="root", password=random_text(12), look_for_keys=False)
        except paramiko.AuthenticationException:
            self.ssh_client.close()
            return True

        except socket.error:
            print_error("Connection error", verbose=self.verbosity)
            self.ssh_client.close()
            return False

        except Exception as err:
            print_error("Err: {}".format(err), verbose=self.verbosity)

        self.ssh_client.close()
        return False

    def execute(self, cmd):
        ssh_stdin, ssh_stdout, ssh_stderr = self.ssh_client.exec_command(cmd)
        return ssh_stdout.read()

    def get_file(self, remote_file, local_file):
        sftp = self.ssh_client.open_sftp()
        sftp.get(remote_file, local_file)

    def get_content(self, remote_file):
        fp_content = io.BytesIO()
        sftp = self.ssh_client.open_sftp()
        sftp.getfo(remote_file, fp_content)

        return fp_content.getvalue()

    def send_file(self, local_file, dest_file):
        sftp = self.ssh_client.open_sftp()
        sftp.put(local_file, dest_file)

    def send_content(self, content, dest_file):
        fp_content = io.BytesIO(content)
        sftp = self.ssh_client.open_sftp()
        sftp.putfo(fp_content, dest_file)

    def interactive(self):
        chan = self.ssh_client.invoke_shell()
        if os.name == "posix":
            self._posix_shell(chan)
        else:
            self._windows_shell(chan)

    def _posix_shell(self, chan):
        import termios
        import tty

        oldtty = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
            chan.settimeout(0.0)

            while True:
                r, w, e = select.select([chan, sys.stdin], [], [])
                if chan in r:
                    try:
                        x = str(chan.recv(1024), "utf-8")
                        if len(x) == 0:
                            break

                        sys.stdout.write(x)
                        sys.stdout.flush()
                    except socket.timeout:
                        pass

                if sys.stdin in r:
                    x = sys.stdin.read(1)
                    if len(x) == 0:
                        break
                    chan.send(x)
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
            return

    def _windows_shell(self, chan):
        def writeall(sock):
            while True:
                data = sock.recv(256)
                if not data:
                    sys.stdout.flush()
                    return

                sys.stdout.write(data)
                sys.stdout.flush()

        writer = threading.Thread(target=writeall, args=(chan,))
        writer.start()

        try:
            while True:
                d = sys.stdin.read(1)
                if not d:
                    break

                chan.send(d)

        except Exception as err:
            print_error("Err: {}".format(err), verbose=self.verbosity)

    def close(self):
        self.ssh_client.close()
        return None


class SSHClient(Exploit):
    """ SSH Client exploit """

    target_protocol = Protocol.SSH

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def ssh_create(self, target=None, port=None):
        ssh_target = target if target else self.target
        ssh_port = port if port else self.port

        ssh_client = SSHCli(ssh_target, ssh_port, verbosity=self.verbosity)
        return ssh_client
