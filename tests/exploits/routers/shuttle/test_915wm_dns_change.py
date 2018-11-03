from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.exploits.routers.shuttle.915wm_dns_change")


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/dnscfg.cgi", methods=["POST"])
    route_mock.retur_value = (
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
