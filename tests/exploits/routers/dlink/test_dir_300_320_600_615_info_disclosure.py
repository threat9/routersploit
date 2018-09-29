from routersploit.modules.exploits.routers.dlink.dir_300_320_600_615_info_disclosure import Exploit


def test_exploit_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/model/__show_info.php", methods=["GET"])
    route_mock.return_value = (
        "test"
        "\n\t\t\tadmin:Password1234\n\n\t\t\t"
        "test"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
