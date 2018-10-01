from unittest import mock
from routersploit.modules.exploits.routers.asmax.ar_804_gu_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.asmax.ar_804_gu_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/cgi-bin/script", methods=["GET"])
    route_mock.return_value = (
        "root:x:0:0:root:/root:/bin/bash"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin"
        "sync:x:4:65534:sync:/bin:/bin/sync"
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin"
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin"
        "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin"
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin"
        "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin"
        "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin"
        "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
