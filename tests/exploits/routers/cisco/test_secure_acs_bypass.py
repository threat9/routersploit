from routersploit.modules.exploits.routers.cisco.secure_acs_bypass import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 443
    assert exploit.ssl is True
    assert exploit.path == "/PI/services/UCP/"
    assert exploit.username == ""
    assert exploit.password == ""

    exploit.target = target.host
    exploit.port = target.port
    exploit.ssl = "false"

    assert exploit.check() is None
    assert exploit.run() is None
