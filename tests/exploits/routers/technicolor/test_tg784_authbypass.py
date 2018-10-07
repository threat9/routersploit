from routersploit.modules.exploits.routers.technicolor.tg784_authbypass import Exploit


def test_check_success(target):
    """ Test scenario - successful exploitation """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 21
    assert exploit.username == "upgrade"
    assert exploit.password == "Th0ms0n!"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is False
    assert exploit.run() is None
