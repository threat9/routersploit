from routersploit.modules.exploits.routers.cisco.firepower_management60_rce import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/img/favicon.png?v=6.0.1-1213", methods=["GET"])
    route_mock.return_value = (
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 443
    assert exploit.ssl is True
    assert exploit.ssh_port == 22
    assert exploit.username == "admin"
    assert exploit.password == "Admin123"
    assert exploit.newusername == ""
    assert exploit.newpassword == ""

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is False
    assert exploit.run() is None
