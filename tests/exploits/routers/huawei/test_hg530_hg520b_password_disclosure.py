from routersploit.modules.exploits.routers.huawei.hg530_hg520b_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    cgi_mock = target.get_route_mock("/UD/", methods=["POST"])
    cgi_mock.return_value = (
        'TEST'
        '<NewUserpassword>Admin1234</NewUserpassword>'
        'TEST'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
