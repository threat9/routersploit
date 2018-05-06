# Contribution Guidelines

There are many ways to contribute to RouterSploit project, and the routersploit team is grateful for all contributions. This overview summarizes the most important steps to get you started as a contributor.

* Report bugs to the routersploit issue tracker.
* Make suggestions for changes, updates, or new features to the routersploit issue tracker.
* Contribute bug fixes, example code, documentation, or tutorials to routersploit.
* Contribute new features to routersploit.

## Bug reports

When submitting bug reports, please consider providing the following information:

* Reproduction steps: step by step description to reproduce the problem.
* Expected: Describe the behavior you expect.
* Actual: Describe the behavior you see.

## Testing
It is hard to test modules in all possible scenarios. If you would like to help:

1. Check what device you have - identify vendor and version.
2. Check if routersploit contains exploits for the device you posses.
3. If exploit does not work but it should, check "show info" for more information. References should provide you with links to proof of concept exploits.

Example:
```
References:
-  https://www.exploit-db.com/exploits/24975/
```

4. Try to use proof of concept exploit and check if it works properly. If it does, feel free to create new issue bug with explanation that the routersploit's module does not work properly.

## Development
* [Creating exploit module](https://github.com/reverse-shell/routersploit/wiki/Creating-Exploit)
* [Creating creds module](https://github.com/reverse-shell/routersploit/wiki/Creating-Creds)
* [Creating scanner module](https://github.com/reverse-shell/routersploit/wiki/Creating-Scanner)
