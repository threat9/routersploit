from routersploit.core.exploit.utils import import_exploit

# hack to import from directory/filename starting with a number
Exploit = import_exploit("routersploit.modules.exploits.routers.3com.imc_info_disclosure")


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/imc/reportscript/sqlserver/deploypara.properties", methods=["GET"])
    route_mock.return_value = (
        "TEST"
        "report.db.server.name=ABCD"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 8080

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
