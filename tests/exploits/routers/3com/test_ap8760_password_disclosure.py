from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.exploits.routers.3com.ap8760_password_disclosure")


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/s_brief.htm", methods=["GET"])
    route_mock.return_value = (
        "TEST"
        "<input type=\"text\" name=\"szUsername\" size=16 value=\"admin\">"
        "<input type=\"password\" name=\"szPassword\" size=16 maxlength=\"16\" value=\"admin\">"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
