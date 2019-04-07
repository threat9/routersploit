#!/bin/bash

set -e
set -x

if [[ "$(uname -s)" == 'Darwin' ]]; then
    sw_vers

    git clone --depth 1 https://github.com/yyuu/pyenv.git ~/.pyenv
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"

    pyenv install $PYTHON_VERSION
    pyenv global $PYTHON_VERSION
    pyenv rehash

    pip install --user virtualenv
    python -m virtualenv ~/.venv
    source ~/.venv/bin/activate
fi

python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
