from unittest import mock
from routersploit.modules.exploits.routers.dlink.dsl_2750b_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.dlink.dsl_2750b_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful exploitation """

    route_mock1 = target.get_route_mock("/login.cgi", methods=["GET"])
    route_mock1.return_value = (
        "TEST"
    )

    route_mock2 = target.get_route_mock("/ayefeaturesconvert.js", methods=["GET"])
    route_mock2.return_value = (
        """
        (..)
        var AYECOM_PRIVATE="private";
        var AYECOM_AREA="EU";
        var AYECOM_FWVER="1.01";
        var AYECOM_HWVER="D1";
        var AYECOM_PRIVATEDIR="private";
        var AYECOM_PROFILE="DSL-2750B";
        var FIRST_HTML="";
        var BUILD_GUI_VERSIOIN_EU="y";
        // BUILD_GUI_VERSIOIN_AU is not s
        (..)
        """
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
