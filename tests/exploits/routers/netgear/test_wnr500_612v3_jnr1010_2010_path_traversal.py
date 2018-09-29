from routersploit.modules.exploits.routers.netgear.wnr500_612v3_jnr1010_2010_path_traversal import Exploit


def test_exploit_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/cgi-bin/webproc", methods=["GET"])
    route_mock.return_value = (
        "#root:$1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.:13796:0:99999:7:::"
        "root:$1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.:13796:0:99999:7:::"
        "#tw:$1$zxEm2v6Q$qEbPfojsrrE/YkzqRm7qV/:13796:0:99999:7:::"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.username == "admin"
    assert exploit.password == "password"
    assert exploit.filename == "/etc/shadow"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
