from routersploit.modules.exploits.routers.billion.billion_7700nr4_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/backupsettings.conf", methods=["GET"])
    route_mock.return_value = (
        "test"
        "<AdminPassword>Admin1234Password</AdminPassword>"
        "test"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.def_user == "user"
    assert exploit.def_pass == "user"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
