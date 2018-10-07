from routersploit.modules.exploits.routers.dlink.dsl_2730b_2780b_526b_dns_change import Exploit


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/dnscfg.cgi", methods=["POST"])
    route_mock.return_value = (
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.dns1 == "8.8.8.8"
    assert exploit.dns2 == "8.8.4.4"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is None
    assert exploit.run() is None
