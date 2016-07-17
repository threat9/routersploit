#!/usr/bin/env bash
IFS=' '
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color
MODULES_PATH=./routersploit/modules
FAILURE=0

PEP=$(pep8 --ignore E501,W503 $MODULES_PATH)
PYFLAKES=$(pyflakes $MODULES_PATH)

if [ "$PEP" ]; then
    echo -e "${RED}- PEP8 violations:${NC}"
    echo -e $PEP
    echo ""
    FAILURE=1
else
    echo -e "${GREEN}+ PEP8${NC}"
fi

if [ "$PYFLAKES" ]; then
    echo -e "\n${RED}- pyflakes violations:${NC}"
    echo -e $PYFLAKES
    echo "\n"
    FAILURE=1 
else
    echo -e "${GREEN}+ pyflakes${NC}"
fi

exit $FAILURE
