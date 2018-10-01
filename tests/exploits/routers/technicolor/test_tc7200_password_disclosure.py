from routersploit.modules.exploits.routers.technicolor.tc7200_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/goform/system/GatewaySettings.bin", methods=["GET"])
    route_mock.return_value = (
        "TEST"
        "0MLog"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
