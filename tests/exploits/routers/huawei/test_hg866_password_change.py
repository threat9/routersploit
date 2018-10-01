from routersploit.modules.exploits.routers.huawei.hg866_password_change import Exploit


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/html/password.html", methods=["GET"])
    route_mock.return_value = (
        'TEST'
        'psw'
        'TEST'
        'reenterpsw'
        'TEST'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.password == "routersploit"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
