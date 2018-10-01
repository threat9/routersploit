from routersploit.modules.exploits.routers.dlink.dir_300_320_615_auth_bypass import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/bsc_lan.php", methods=["GET"])
    route_mock.return_value = (
        '<form name="frm" id="frm" method="post" action="login.php">'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is False
    assert exploit.run() is None
