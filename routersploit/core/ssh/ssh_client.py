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


class SSHClient(Exploit):
    """ SSH Client exploit """

    target_protocol = Protocol.SSH

    verbosity = OptBool("true", "Enable verbose output: true/false")

    def ssh_create(self):
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        return ssh_client

    def ssh_login(self, username, password, retries=1):
        ssh_client = self.ssh_create()

        for _ in range(retries):
            try:
                ssh_client.connect(self.target, self.port, timeout=SSH_TIMEOUT, banner_timeout=SSH_TIMEOUT, username=username, password=password, look_for_keys=False)
            except paramiko.AuthenticationException:
                print_error("SSH Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                ssh_client.close()
                break
            except Exception as err:
                print_error("Err: {}".format(err), verbose=self.verbosity)
            else:
                print_success("SSH Authentication Successful - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                return ssh_client

            ssh_client.close()

        return

    def ssh_login_pkey(self, username, priv_key, retries=1):
        ssh_client = self.ssh_create()

        if "DSA PRIVATE KEY" in priv_key:
            priv_key = paramiko.DSSKey.from_private_key(io.StringIO(priv_key))
        elif "RSA PRIVATE KEY" in priv_key:
            priv_key = paramiko.RSAKey.from_private_key(io.StringIO(priv_key))
        else:
            return None

        for _ in range(retries):
            try:
                ssh_client.connect(self.target, self.port, timeout=SSH_TIMEOUT, banner_timeout=SSH_TIMEOUT, username=username, pkey=priv_key, look_for_keys=False)
            except paramiko.AuthenticationException:
                print_error("Authentication Failed - Username: '{}' auth with private key".format(username), verbose=self.verbosity)
            except Exception as err:
                print_error("Err: {}".format(err), verbose=self.verbosity)
            else:
                print_success("SSH Authentication Successful - Username: '{}' with private key".format(username), verbose=self.verbosity)
                return ssh_client

            ssh_client.close()

        return None

    def ssh_test_connect(self):
        ssh_client = self.ssh_create()

        try:
            ssh_client.connect(self.target, self.port, timeout=SSH_TIMEOUT, username="root", password=random_text(12), look_for_keys=False)
        except paramiko.AuthenticationException:
            ssh_client.close()
            return True

        except socket.error:
            print_error("Connection error", verbose=self.verbosity)
            ssh_client.close()
            return False

        except Exception as err:
            print_error("Err: {}".format(err), verbose=self.verbosity)

        ssh_client.close()
        return False

    def ssh_execute(self, ssh, cmd):
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
        return ssh_stdout.read()

    def ssh_get_file(self, ssh, remote_file, local_file):
        sftp = ssh.open_sftp()
        sftp.get(remote_file, local_file)

    def ssh_get_content(self, ssh, remote_file):
        fp_content = io.BytesIO()
        sftp = ssh.open_sftp()
        sftp.getfo(remote_file, fp_content)

        return fp_content.getvalue()

    def ssh_send_file(self, ssh, local_file, dest_file):
        sftp = ssh.open_sftp()
        sftp.put(local_file, dest_file)

    def ssh_send_content(self, ssh, content, dest_file):
        fp_content = io.BytesIO(content)
        sftp = ssh.open_sftp()
        sftp.putfo(fp_content, dest_file)

    def ssh_interactive(self, ssh):
        if ssh:
            chan = ssh.invoke_shell()
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

    def ssh_close(self, ssh_client):
        if ssh_client:
            ssh_client.close()

        return None
