from unittest import mock
from routersploit.modules.exploits.routers.linksys.eseries_themoon_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.linksys.eseries_themoon_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/tmUnblock.cgi", methods=["GET", "POST"])
    route_mock.return_value = ""

    exploit = Exploit()
    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
