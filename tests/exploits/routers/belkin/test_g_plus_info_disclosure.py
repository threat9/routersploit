from routersploit.modules.exploits.routers.belkin.g_plus_info_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/SaveCfgFile.cgi", methods=["GET"])
    route_mock.return_value = (
        'test'
        'pppoe_username'
        'pppoe_password'
        'wl0_pskkey'
        'wl0_key1'
        'mradius_password'
        'mradius_secret'
        'httpd_password'
        'http_passwd'
        'pppoe_passwd'
        'test'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
