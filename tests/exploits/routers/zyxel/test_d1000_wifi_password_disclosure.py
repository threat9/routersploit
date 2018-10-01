from routersploit.modules.exploits.routers.zyxel.d1000_wifi_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/UD/act", methods=["POST"])
    route_mock.return_value = (
        "TEST"
        "<NewPreSharedKey>Admin1234</NewPreSharedKey>"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 7547

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
