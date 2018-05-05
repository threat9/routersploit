#!/usr/bin/env python

from __future__ import print_function

import argparse
import logging.handlers

from routersploit.interpreter import RoutersploitInterpreter

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
    routersploit()
