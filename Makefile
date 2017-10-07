.PHONY: build run test lint lint-modules clean prune help

MODULE=''
RSF_IMAGE=routersploit

build:
	docker build -t $(RSF_IMAGE) .

run:
	docker run -it --rm $(RSF_IMAGE)

lint:
	./run_linter.sh

lint-modules:
	./run_linter.sh modules

test: clean
	./run_tests.sh $(MODULE)

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
