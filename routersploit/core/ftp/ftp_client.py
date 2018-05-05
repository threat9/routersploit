import socket
import ftplib

from routersploit.core.exploit.exploit import Exploit
from routersploit.core.exploit.exploit import Protocol
from routersploit.core.exploit.option import OptBool
from routersploit.core.exploit.printer import print_error


FTP_TIMEOUT = 30.0


class FTPClient(Exploit):
    """ FTP Client exploit """

    target_protocol = Protocol.FTP

    ssl = OptBool("false", "SSL enabled: true/false")
    verbosity = OptBool("true", "Enable verbose output: true/false")

    def ftp_create(self):
        if self.ssl:
            ftp_client = ftplib.FTP_TLS()
        else:
            ftp_client = ftplib.FTP()

        return ftp_client

    def ftp_connect(self, retries=1):
        ftp_client = self.ftp_create()

        for _ in range(retries):
            try:
                ftp_client.connect(self.target, self.port, timeout=FTP_TIMEOUT)
            except (socket.error, socket.timeout):
                print_error("Connection error")
            except Exception as err:
                print_error(err)
            else:
                return ftp_client

            ftp_client.close()
        return None

    def ftp_login(self, username, password):
        ftp_client = self.ftp_connect()
        if ftp_client:
            try:
                ftp_client.login(username, password)
                return ftp_client
            except Exception as err:
                pass

            ftp_client.close()

        return None
        
    def ftp_test_connect(self):
        ftp_client = self.ftp_connect()
        if ftp_client:
            ftp_client.close()
            return True

        return False
