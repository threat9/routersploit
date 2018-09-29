from routersploit.modules.exploits.routers.cisco.dpc2420_info_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/filename.gwc", methods=["GET"])
    route_mock.return_value = (
        "User Password"
        "Admin1234"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 8080

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
