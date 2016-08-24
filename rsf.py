#!/usr/bin/env python2

from __future__ import print_function

import argparse
import logging.handlers

from routersploit.interpreter import RoutersploitInterpreter
from routersploit.utils import create_exploit

log_handler = logging.handlers.RotatingFileHandler(filename='routersploit.log', maxBytes=500000)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s       %(message)s')
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)

parser = argparse.ArgumentParser(description='RouterSploit - Router Exploitation Framework')
parser.add_argument('-a',
                    '--add-exploit',
                    metavar='exploit_path',
                    help='Add exploit using default template.')


def routersploit():
    rsf = RoutersploitInterpreter()
    rsf.start()

if __name__ == "__main__":
    args = parser.parse_args()

    if args.add_exploit:
        create_exploit(args.add_exploit)
    else:
        routersploit()
