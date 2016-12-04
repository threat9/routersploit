#!/usr/bin/env bash

if [ -z $1 ] ; then
    docker run -it --net host --rm routersploit
else
    docker run -it --net host --rm routersploit $@
fi
