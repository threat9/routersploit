from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.exploits.routers.3com.officeconnect_info_disclosure")


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/SaveCfgFile.cgi", methods=["GET"])
    route_mock.return_value = (
        "TEST"
        "pppoe_username=admin"
        "pppoe_password=admin"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
