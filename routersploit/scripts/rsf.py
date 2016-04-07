#!/usr/bin/env python

from routersploit.interpreter import RoutersploitInterpreter


def routersploit():
    rsf = RoutersploitInterpreter()
    rsf.start()

if __name__ == "__main__":
    routersploit()
