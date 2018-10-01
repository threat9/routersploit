from routersploit.modules.exploits.routers.comtrend.ct_5361t_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/password.cgi", methods=["GET"])
    route_mock.return_value = (
        "test"
        "pwdAdmin = 'QWRtaW4=';"
        "pwdSupport = 'QWRtaW4=';"
        "pwdUser = 'QWRtaW4=';"
        "test"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
