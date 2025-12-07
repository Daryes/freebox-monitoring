.PHONY: no_targets__ all list help
.DEFAULT_GOAL=help
list: ## Show all the existing targets of this Makefile
	@sh -c "$(MAKE) -p no_targets__ 2>/dev/null | awk -F':' '/^[a-zA-Z0-9][^\$$#\/\\t=]*:([^=]|$$)/ {split(\$$1,A,/ /);for(i in A)print A[i]}' | egrep -v '(__\$$|^Makefile.*)' | sort -u"

help: ## Show the targets and their description (this screen)
	@grep --no-filename -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort -h | awk 'BEGIN {FS = ": .*?## "}; {printf "\033[36m%-40s\033[0m %s\n", $$1, $$2}'


# Global settings -----------------------------------
SHELL=/bin/bash -o pipefail

# Application name
APP_NAME:=freebox-monitoring
PROJECT_NAME:=freebox-monitoring
TAG_VERSION ?=latest

DOCKER_IMAGE_NAME:=custom/${APP_NAME}

# mandatory default values
MAKEFILE_DIR:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
JENKINS_WRNG:=warnings-ng.jks
REPORT_DIR ?=$(MAKEFILE_DIR)/reports
BUILD_DIR ?=$(MAKEFILE_DIR)/builds


requirements: ## install python requirements
	@python3 -m pip install --no-cache-dir -r requirements.txt


docker-build: ## build the docker image
	@# buildx is still not able to reuse the local images - https://github.com/docker/buildx/issues/847
	@DOCKER_BUILDKIT=0 docker-compose build


test-syntax-1-pylint: ## run pylint - syntax : make test-syntax-1-pylint [ REPORT_DIR=/path/output ]
	@pylint --version
	@if [ -d ${REPORT_DIR} ]; then echo "PyLint" > ${REPORT_DIR}/${JENKINS_WRNG} ;\
		pylint --rcfile .ci/pylint -f parseable --output ${REPORT_DIR}/pylint.log --exit-zero . ;\
	else pylint --rcfile .ci/pylint . ; fi


# short execution to only check the validity of the code (declared variable, basic syntax, ...)
test-syntax-2-flake8-validity: ## run flake8 in validity mode - syntax : make test-syntax-2-flake8-validity [ REPORT_DIR=/path/output ]
	@flake8 --version
	@if [ -d ${REPORT_DIR} ]; then echo 'Flake8' > ${REPORT_DIR}/${JENKINS_WRNG} ;\
		export FLAKE_PARAMS='--format=default --output-file ${REPORT_DIR}/flake8.log --exit-zero --tee --benchmark' ;\
	fi ;\
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics  $${FLAKE_PARAMS}


test-syntax-3-flake8: ## run flake8 - syntax : make test-syntax-3-flake8 [ REPORT_DIR=/path/output ]
	@flake8 --version
	@if [ -d ${REPORT_DIR} ]; then echo 'Flake8' > ${REPORT_DIR}/${JENKINS_WRNG} ;\
		export FLAKE_PARAMS='--format=default --output-file ${REPORT_DIR}/flake8.log --exit-zero --tee' ;\
	fi ;\
	flake8 . --config=.ci/flake8.ini  $${FLAKE_PARAMS}


test-syntax-4-hadolint: ## run hadolint - syntax : make test-syntax-4-hadolint [ REPORT_DIR=/path/output ]
	@hadolint --version
	@echo "HadoLint" > $(REPORT_DIR)/$(JENKINS_WRNG)
	@hadolint --config .ci/hadolint.yml --no-fail --format json docker/Dockerfile | tee $(REPORT_DIR)/hadolint.log


test-syntax-5-trivy: ## run trivy - syntax : make test-syntax-5-trivy [ REPORT_DIR=/path/output ]
	@echo "Trivy" > $(REPORT_DIR)/$(JENKINS_WRNG)
	@trivy-offline.sh fs --exit-code 0 --format json  --output $(REPORT_DIR)/trivy.json .


# vim: noexpandtab filetype=make