from routersploit.modules.exploits.routers.technicolor.dwg855_authbypass import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/logo.jpg", methods=["GET"])
    route_mock.return_value = (
        b"\x11\x44\x75\x63\x6b\x79\x00"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.nuser == "ruser"
    assert exploit.npass == "rpass"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
