from routersploit.modules.exploits.routers.dlink.dwl_3200ap_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/", methods=["GET"])
    route_mock.return_value = (
        "TEST"
        "RpWebID=a3b21ada\n"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.seconds == 3600

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
