#!/usr/bin/env python3

from __future__ import print_function
import logging.handlers
import sys
if sys.version_info.major < 3:
    print("RouterSploit supports only Python3. Rerun application in Python3 environment.")
    exit(0)

from routersploit.interpreter import RoutersploitInterpreter

log_handler = logging.handlers.RotatingFileHandler(filename="routersploit.log", maxBytes=500000)
log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s       %(message)s")
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)


def routersploit(argv):
    rsf = RoutersploitInterpreter()
    if len(argv[1:]):
        rsf.nonInteractive(argv)
    else:
        rsf.start()

if __name__ == "__main__":
    try:
        routersploit(sys.argv)
    except (KeyboardInterrupt, SystemExit):
        pass
