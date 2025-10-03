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


# mandatory default values
MAKEFILE_DIR:=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
JENKINS_WRNG:=warnings-ng.jks
REPORT_DIR ?=$(MAKEFILE_DIR)/reports
BUILD_DIR ?=$(MAKEFILE_DIR)/builds


requirements: ## install python requirements
	@python3 -m pip install --no-cache -r requirements.txt


test-syntax-1-pylint: ## run pylint - syntax : make test-syntax-1-pylint [ REPORT_DIR=/path/output ]
	@pylint --version
	@if [ -d ${REPORT_DIR} ]; then \
		pylint --rcfile .ci/pylint -f parseable --output ${REPORT_DIR}/pylint.log --exit-zero . && \
		echo "PyLint" > ${REPORT_DIR}/${JENKINS_WRNG} ;\
	else pylint --rcfile .ci/pylint . ; fi


# vim: noexpandtab filetype=make