from routersploit.modules.exploits.routers.linksys.smartwifi_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/.htpasswd", methods=["GET"])
    route_mock.return_value = (
        'admin:$1$3Eb757jl$zFM3Mtk8Qmkp3kjbRukUq/'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
