from unittest import mock
from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.exploits.routers.3com.officeconnect_rce")


@mock.patch("routersploit.modules.exploits.routers.3com.officeconnect_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/utility.cgi", methods=["GET"])
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
    assert exploit.execute("uname -a") == ""
