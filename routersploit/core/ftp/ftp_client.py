import ftplib
import io

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_error
from routersploit.core.exploit.printer import print_success


FTP_TIMEOUT = 8.0


class FTPCli(object):
    """ FTP Client """

    def __init__(self, ftp_target, ftp_port, ssl=False, verbosity=False):
        self.ftp_target = ftp_target
        self.ftp_port = ftp_port
        self.verbosity = verbosity

        self.peer = "{}:{}".format(self.ftp_target, ftp_port)

        if ssl:
            self.ftp_client = ftplib.FTP_TLS()
        else:
            self.ftp_client = ftplib.FTP()

    def connect(self, retries=1):
        for _ in range(retries):
            try:
                self.ftp_client.connect(self.ftp_target, self.ftp_port, timeout=FTP_TIMEOUT)
                return self.ftp_client
            except Exception as err:
                print_error(self.peer, "FTP Error while connecting to the server", err, verbose=self.verbosity)

            self.ftp_client.close()

        return None

    def login(self, username, password):
        try:
            self.ftp_client.login(username, password)
            print_success(self.peer, "FTP Authentication Successful - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)
            return self.ftp_client
        except Exception as err:
            print_error(self.peer, "FTP Authentication Failed - Username: '{}' Password: '{}'".format(username, password), verbose=self.verbosity)

        self.ftp_client.close()
        return None

    def test_connect(self):
        if self.connect():
            self.ftp_client.close()
            return True

        return False

    def get_content(self, remote_file):
        try:
            fp_content = io.BytesIO()
            self.ftp_client.retrbinary("RETR {}".format(remote_file), fp_content.write)
            return fp_content.getvalue()
        except Exception as err:
            print_error(self.peer, "FTP Error while retrieving content", err, verbose=self.verbosity)

        return None

    def close(self):
        try:
            self.ftp_client.close()
        except Exception as err:
            print_error(self.peer, "FTP Error while closing connection", err, verbose=self.verbosity)

        return None


class FTPClient(Exploit):
    """ FTP Client exploit option and api """

    target_protocol = Protocol.FTP

    ssl = OptBool(False, "SSL enabled: true/false")
    verbosity = OptBool(True, "Enable verbose output: true/false")

    def ftp_create(self, target=None, port=None):
        ftp_target = target if target else self.target
        ftp_port = port if port else self.port

        ftp_client = FTPCli(ftp_target, ftp_port, ssl=self.ssl, verbosity=self.verbosity)
        return ftp_client
