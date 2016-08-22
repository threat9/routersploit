#!/usr/bin/env bash

TEST_PATH="routersploit.test"

if [ -z $1 ] ; then
    python -m unittest discover
else
    for param in "$@" ; do
        PARAMS="$PARAMS $TEST_PATH.$param"
    done
    python -m unittest $PARAMS
fi
