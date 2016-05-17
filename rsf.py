#!/usr/bin/env python2

from __future__ import print_function
import os
import argparse

from routersploit.interpreter import RoutersploitInterpreter
from routersploit.utils import create_resource, Resource
from routersploit.templates import exploit


parser = argparse.ArgumentParser(description='RouterSploit - Router Exploitation Framework')
parser.add_argument('--add-exploit',
                    metavar='exploit_path',
                    help='Add exploit using default template.')


def routersploit():
    rsf = RoutersploitInterpreter()
    rsf.start()

if __name__ == "__main__":
    args = parser.parse_args()

    if args.add_exploit:
        base, _, name = args.add_exploit.rpartition(os.sep)
        create_resource(
            name=base,
            content=(
                Resource(
                    name="{}.py".format(name),
                    template_path=os.path.abspath(exploit.__file__.rstrip("c")),
                    context={}),
            ),
            python_package=True
        )
    else:
        routersploit()
