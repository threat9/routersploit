.PHONY: build run test lint lint-modules clean prune help

DIRECTORY=.
EXCLUDED=.git,rsf.py
RSF_IMAGE=routersploit
FLAKE8_IGNORED_RULES=E501,F405,F403

build:
	docker build -t $(RSF_IMAGE) .

run:
	docker run -it --rm $(RSF_IMAGE)

lint:
	python3 -m flake8 --exclude=$(EXCLUDED) --ignore=$(FLAKE8_IGNORED_RULES) $(DIRECTORY)

tests: clean
	python3 -m pytest -n16 tests 

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
	@echo "    test"
	@echo "        Run test suite"
	@echo "    clean"
	@echo "        Remove python artifacts."
	@echo "    prune"
	@echo "        Remove dangling docker images and exited containers."
