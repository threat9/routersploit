from unittest import mock
from routersploit.modules.exploits.routers.netsys.multi_rce import Exploit


etc_passwd = (
    "#root:$1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.:13796:0:99999:7:::"
    "root:$1$BOYmzSKq$ePjEPSpkQGeBcZjlEeLqI.:13796:0:99999:7:::"
    "#tw:$1$zxEm2v6Q$qEbPfojsrrE/YkzqRm7qV/:13796:0:99999:7:::"
)


@mock.patch("routersploit.modules.exploits.routers.netsys.multi_rce.shell")
def test_check_v1_success(mocked_shell, target):
    """ Test scenario - successful check via method 1 """

    route_mock = target.get_route_mock("/view/IPV6/ipv6networktool/traceroute/ping.php", methods=["GET"])
    route_mock.return_value = etc_passwd

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 9090

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None


@mock.patch("routersploit.modules.exploits.routers.netsys.multi_rce.shell")
def test_check_v2_success(mocked_shell, target):
    """ Test scenario - successful check via method 2 """

    route_mock = target.get_route_mock("/view/systemConfig/systemTool/ping/ping.php", methods=["GET"])
    route_mock.return_value = etc_passwd

    exploit = Exploit()

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None


@mock.patch("routersploit.modules.exploits.routers.netsys.multi_rce.shell")
def test_check_v3_success(mocked_shell, target):
    """ Test scenario - successful check via method 3 """

    route_mock = target.get_route_mock("/view/systemConfig/systemTool/traceRoute/traceroute.php", methods=["GET"])
    route_mock.return_value = etc_passwd

    exploit = Exploit()

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
