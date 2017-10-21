.PHONY: build run test lint lint-modules clean prune help

MODULES=routersploit
RSF_IMAGE=routersploit
FLAKE8_IGNORED_RULES=E501,W503

build:
	docker build -t $(RSF_IMAGE) .

run:
	docker run -it --rm $(RSF_IMAGE)

lint:
	flake8 --exclude=__init__.py --ignore=$(FLAKE8_IGNORED_RULES) tests $(MODULES)

tests: clean
ifeq ($(MODULES), routersploit)
	python -m unittest discover
else
	python -m unittest $(MODULES)
endif

clean:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +

prune:
	docker images -q -f dangling=true | xargs docker rmi
	docker ps -q -f status=exited | xargs docker rm

help:
	@echo "    run"
	@echo "        Run Routersploit in docker container"
	@echo "    lint"
	@echo "        Check style with flake8."
	@echo "    lint-modules"
	@echo "        Check modules style with flake8."
	@echo "    test"
	@echo "        Run test suite"
	@echo "    clean"
	@echo "        Remove python artifacts."
	@echo "    prune"
	@echo "        Remove dangling docker images and exited containers."
