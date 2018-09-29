from routersploit.modules.exploits.routers.dlink.dir_850l_creds_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    cgi_mock = target.get_route_mock("/hedwig.cgi", methods=["POST"])
    cgi_mock.return_value = (
        "<module>"
        "<service></service>"
        "<device>"
        "<gw_name>DIR-850L</gw_name>"
        "<account>"
        "<seqno>1</seqno>"
        "    <max>2</max>"
        "    <count>1</count>"
        "    <entry>"
        "    <uid>USR-</uid>"
        "    <name>Admin</name>"
        "    <usrid></usrid>"
        "    <password>92830535</password>"
        "    <group>0</group>"
        "    <description></description>"
        "    </entry>"
        "    </account>"
        "    <group>"
        "    <seqno></seqno>"
        "    <max></max>"
        "    <count>0</count>"
        "    </group>"
        "    <session>"
        "    <captcha>0</captcha>"
        "    <dummy></dummy>"
        "    <timeout>180</timeout>"
        "    <maxsession>128</maxsession>"
        "    <maxauthorized>16</maxauthorized>"
        "    </session>"
        "    </device>"
        "    </module>"
        "    <?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "    <hedwig>"
        "    <result>OK</result>"
        "    <node></node>"
        "    <message>No modules for Hedwig</message>"
        "    </hedwig>"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
