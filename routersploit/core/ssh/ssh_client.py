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
    """ SSH Client provides methods to handle communication with SSH server """

    def __init__(self, ssh_target: str, ssh_port: int, verbosity: bool = False) -> None:
        """ SSH client constructor

        :param str ssh_target: SSH target ip address
        :param int ssh_port: SSH port number
        :param bool verbosity: display verbose output
        :return None:
        """

        self.ssh_target = ssh_target
        self.ssh_port = ssh_port
        self.verbosity = verbosity

        self.peer = "{}:{}".format(self.ssh_target, self.ssh_port)

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def login(self, username: str, password: str, retries: int = 1) -> bool:
        """ Login to SSH server

        :param str username: SSH account username
        :param str password: SSH account password
        :param int retries: number of login retries
        :return bool: True if login was successful, False otherwise
        """

        for _ in range(retries):
            try:
                self.ssh_client.connect(
                    self.ssh_target,
                    self.ssh_port,
                    timeout=SSH_TIMEOUT,
                    banner_timeout=SSH_TIMEOUT,
                    username=username,
                    password=password,
                    look_for_keys=False,
                    allow_agent=False,
                )
            except paramiko.AuthenticationException:
                print_error(self.peer, "SSH Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                self.ssh_client.close()
                break
            except Exception as err:
                print_error(self.peer, "SSH Error while authenticating", err, verbose=self.verbosity)
            else:
                print_success(self.peer, "SSH Authentication Successful - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
                return True

            self.ssh_client.close()

        return False

    def login_pkey(self, username: str, priv_key: str, retries: int = 1) -> bool:
        """ Login to SSH server with private key

        :param str username: SSH account username
        :param str priv_key: SSH account private key
        :param int retries: number of login retries
        :return bool: True if login was successful, False otherwise
        """

        if "DSA PRIVATE KEY" in priv_key:
            priv_key = paramiko.DSSKey.from_private_key(io.StringIO(priv_key))
        elif "RSA PRIVATE KEY" in priv_key:
            priv_key = paramiko.RSAKey.from_private_key(io.StringIO(priv_key))
        else:
            return False

        for _ in range(retries):
            try:
                self.ssh_client.connect(
                    self.ssh_target,
                    self.ssh_port,
                    timeout=SSH_TIMEOUT,
                    banner_timeout=SSH_TIMEOUT,
                    username=username,
                    pkey=priv_key,
                    look_for_keys=False,
                    allow_agent=False,
                )
            except paramiko.AuthenticationException:
                print_error(self.peer, "SSH Authentication Failed - Username: '{}' auth with private key".format(username), verbose=self.verbosity)
            except Exception as err:
                print_error(self.peer, "SSH Error while authenticated by using private key", err, verbose=self.verbosity)
            else:
                print_success(self.peer, "SSH Authentication Successful - Username: '{}' with private key".format(username), verbose=self.verbosity)
                return True

            self.ssh_client.close()

        return False

    def test_connect(self) -> bool:
        """ Test connection to SSH server

        :return bool: True if test connection was successful, False otherwise
        """

        try:
            self.ssh_client.connect(
                self.ssh_target,
                self.ssh_port,
                timeout=SSH_TIMEOUT,
                username="root",
                password=random_text(12),
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.AuthenticationException:
            self.ssh_client.close()
            return True
        except Exception as err:
            print_error(self.peer, "SSH Error while testing connection", err, verbose=self.verbosity)

        self.ssh_client.close()
        return False

    def execute(self, cmd: str) -> str:
        """ Execute command on SSH server

        :param str cmd: command to execute on SSH server
        :return str: command output
        """

        try:
            ssh_stdin, ssh_stdout, ssh_stderr = self.ssh_client.exec_command(cmd)
            return ssh_stdout.read()
        except Exception as err:
            print_error(self.peer, "SSH Error while executing command on the server", err, verbose=self.verbosity)

        return None

    def get_file(self, remote_file: str, local_file: str) -> bool:
        """ Get file from SSH server

        :param str remote_file: remote file on SSH server
        :param str local_file: local file that it should be saved to
        :return bool: True if getting file was successful, False otherwise
        """

        try:
            sftp = self.ssh_client.open_sftp()
            sftp.get(remote_file, local_file)

            return True
        except Exception as err:
            print_error(self.peer, "SSH Error while retrieving file from the server", err, verbose=self.verbosity)

        return False

    def get_content(self, remote_file: str) -> str:
        """ Get file content from SSH server

        :param str remote_file: remote file on SSH server
        :return str: file content from SSH server
        """

        try:
            fp_content = io.BytesIO()
            sftp = self.ssh_client.open_sftp()
            sftp.getfo(remote_file, fp_content)

            return fp_content.getvalue()
        except Exception as err:
            print_error(self.peer, "SSH Error while retrieving file content from the server", err, verbose=self.verbosity)

        return None

    def send_file(self, local_file: str, dest_file: str) -> bool:
        """ Send file to SSH server

        :param str local_file: local file that should be send to SSH server
        :param str dest_file: destination file that content should be saved to
        :return bool: True if sending file was successful, False otherwise
        """

        try:
            sftp = self.ssh_client.open_sftp()
            sftp.put(local_file, dest_file)
            return True
        except Exception as err:
            print_error(self.peer, "SSH Error while sending file to the server", err, verbose=self.verbosity)

        return False

    def send_content(self, content: str, dest_file: str) -> bool:
        """ Send file content to SSH server

        :param str content: data that should be sent to SSH file
        :param str dst_file: destination file that data should be saved to
        :return bool: True if sending file content was successful, False otherwise
        """

        try:
            fp_content = io.BytesIO(content)
            sftp = self.ssh_client.open_sftp()
            sftp.putfo(fp_content, dest_file)
            return True
        except Exception as err:
            print_error(self.peer, "SSH Error while sending content to the server", err, verbose=self.verbosity)

        return False

    def interactive(self) -> None:
        """ Start interactive mode with SSH server

        :return None:
        """

        chan = self.ssh_client.invoke_shell()
        if os.name == "posix":
            self._posix_shell(chan)
        else:
            self._windows_shell(chan)

    def _posix_shell(self, chan: paramiko.channel.Channel) -> None:
        """ Start posix shell with SSH server

        :param paramiko.channel.Channel chan: channel for communicating with SSH server
        :return None:
        """

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

    def _windows_shell(self, chan: paramiko.channel.Channel) -> None:
        """ Start Windows shell with SSH server

        :param paramiko.channel.Channel chan: channel for communicating with SSH server
        :return None:
        """

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
            print_error("Error", err, verbose=self.verbosity)

    def close(self) -> bool:
        """ Close SSH connection

        :return bool: True if closing connection was successful, False otherwise
        """

        try:
            self.ssh_client.close()
            return True
        except Exception as err:
            print_error(self.peer, "SSH Error while closing connection", err, verbose=self.verbosity)

        return False


class SSHClient(Exploit):
    """ SSH Client exploit """

    target_protocol = Protocol.SSH

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def ssh_create(self, target: str = None, port: int = None) -> SSHCli:
        """ Create SSH client

        :param str target: target SSH server ip address
        :param int port: target SSH server port
        :return SSHCli: SSH client object
        """

        ssh_target = target if target else self.target
        ssh_port = port if port else self.port

        ssh_client = SSHCli(ssh_target, ssh_port, verbosity=self.verbosity)
        return ssh_client
