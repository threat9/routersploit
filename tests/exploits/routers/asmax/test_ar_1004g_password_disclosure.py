from routersploit.modules.exploits.routers.asmax.ar_1004g_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/password.cgi", methods=["GET"])
    route_mock.return_value = (
        "test"
        "pwdAdmin = 'admin_password';"
        "pwdSupport = 'support_password';"
        "pwdUser = 'user_password';"
        "test"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
