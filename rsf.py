#!/usr/bin/env python2

from __future__ import print_function

import argparse

from routersploit.interpreter import RoutersploitInterpreter
from routersploit.utils import create_exploit


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
