import socket
import ftplib
import io

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_error


FTP_TIMEOUT = 8.0


class FTPCli(object):
    def __init__(self, ftp_target, ftp_port, ssl=False, verbosity=False):
        self.ftp_target = ftp_target
        self.ftp_port = ftp_port
        self.verbosity = verbosity

        if ssl:
            self.ftp_client = ftplib.FTP_TLS()
        else:
            self.ftp_client = ftplib.FTP()

    def connect(self, retries=1):
        for _ in range(retries):
            try:
                self.ftp_client.connect(self.ftp_target, self.ftp_port, timeout=FTP_TIMEOUT)
            except (socket.error, socket.timeout):
                print_error("Connection error", verbose=self.verbosity)
            except Exception as err:
                print_error(err, verbose=self.verbosity)
            else:
                return self.ftp_client

            self.ftp_client.close()
        return None

    def login(self, username, password):
        if self.ftp_client:
            try:
                self.ftp_client.login(username, password)
                return self.ftp_client
            except Exception as err:
                pass

            self.ftp_client.close()
        else:
            print_error("FTP not connected")

        return None

    def test_connect(self):
        if self.connect():
            self.ftp_client.close()
            return True

        return False

    def get_content(self, remote_file):
        fp_content = io.BytesIO()
        self.ftp_client.retrbinary("RETR {}".format(remote_file), fp_content.write)
        return fp_content.getvalue()

    def close(self):
        self.ftp_client.close()
        return None


class FTPClient(Exploit):
    """ FTP Client exploit """

    target_protocol = Protocol.FTP

    ssl = OptBool(False, "SSL enabled: true/false")
    verbosity = OptBool(True, "Enable verbose output: true/false")

    def ftp_create(self, target=None, port=None):
        ftp_target = target if target else self.target
        ftp_port = port if port else self.port

        ftp_client = FTPCli(ftp_target, ftp_port, ssl=self.ssl, verbosity=self.verbosity)
        return ftp_client
