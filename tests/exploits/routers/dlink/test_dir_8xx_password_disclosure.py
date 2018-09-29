from flask import request
from routersploit.modules.exploits.routers.dlink.dir_8xx_password_disclosure import Exploit


def apply_response():
    if "A" not in request.args.keys():
        response = """
<?xml version="1.0" encoding="utf-8"?>
<postxml>
    <result>FAILED</result>
    <message>Not authorized</message>
</postxml>
    """
    else:
        response = """
<?xml version="1.0" encoding="utf-8"?>
<postxml>
<module>
    <service>DEVICE.ACCOUNT</service>
    <device>
        <account>
            <seqno></seqno>
            <max>2</max>
            <count>1</count>
            <entry>
                <uid></uid>
                <name>Admin</name>
                <usrid></usrid>
                <password>RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR</password>
                <group>0</group>
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
            <timeout>300</timeout>
            <maxsession>128</maxsession>
            <maxauthorized>16</maxauthorized>
        </session>
    </device>
</module>
</postxml>
"""
    return response, 200


def test_exploit_success(target):
    """ Test scenario - successful exploitation """

    cgi_mock = target.get_route_mock("/getcfg.php", methods=["GET", "POST"])
    cgi_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
