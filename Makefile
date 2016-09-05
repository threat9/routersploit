# Makefile that aggregates common chores before commit

MODULE=''

all: lint test

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +

lint:
	./run_linter.sh

lint-modules:
	./run_linter.sh modules

test: clean
	./run_tests.sh $(MODULE)

help:
	@echo "    clean"
	@echo "        Remove python artifacts."
	@echo "    lint"
	@echo "        Check style with flake8."
	@echo "    lint-modules"
	@echo "        Check modules style with flake8."
	@echo "    test"
	@echo "        Run test suite"
