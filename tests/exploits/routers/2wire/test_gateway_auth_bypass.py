from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.exploits.routers.2wire.gateway_auth_bypass")


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock1 = target.get_route_mock("/", methods=["GET"])
    route_mock1.return_value = (
        "TEST"
        "<form name=\"pagepost\" method=\"post\" action=\"/xslt?PAGE=WRA01_POST&amp;NEXTPAGE=WRA01_POST\" id=\"pagepost\">"
        "TEST"
    )

    route_mock2 = target.get_route_mock("/xslt", methods=["GET"])
    route_mock2.return_value = (
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
