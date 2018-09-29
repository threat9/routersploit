from routersploit.modules.exploits.routers.asus.rt_n16_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/error_page.htm", methods=["GET"])
    route_mock.return_value = (
        "test"
        "if('1' == '0' || 'admin1234' == 'admin')"
        "test"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 8080

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
