.DEFAULT_GOAL := help

DOCKER_COMPOSE = docker-compose
S2I = script/s2i
REGISTRY ?= quay.io/3scale
export TEST_NGINX_BINARY ?= openresty
NGINX = $(shell which $(TEST_NGINX_BINARY))
SHELL=/bin/bash -o pipefail

NPROC ?= $(firstword $(shell nproc 2>/dev/null) 1)

SEPARATOR="\n=============================================\n"

IMAGE_NAME ?= apicast-test
OPENRESTY_VERSION ?= master
BUILDER_IMAGE ?= quay.io/3scale/s2i-openresty-centos7:$(OPENRESTY_VERSION)
RUNTIME_IMAGE ?= $(BUILDER_IMAGE)-runtime

DEVEL_IMAGE ?= apicast-development
DEVEL_DOCKERFILE ?= Dockerfile-development

DEVEL_DOCKER_COMPOSE_FILE ?= docker-compose-devel.yml
DEVEL_DOCKER_COMPOSE_VOLMOUNT_MAC_FILE ?= docker-compose-devel-volmount-mac.yml
DEVEL_DOCKER_COMPOSE_VOLMOUNT_DEFAULT_FILE ?= docker-compose-devel-volmount-default.yml

os = "$(shell uname -s)"

# if running on Mac
ifeq ($(os),"Darwin")
    DEVEL_DOCKER_COMPOSE_VOLMOUNT_FILE = $(DEVEL_DOCKER_COMPOSE_VOLMOUNT_MAC_FILE)
else
    DEVEL_DOCKER_COMPOSE_VOLMOUNT_FILE = $(DEVEL_DOCKER_COMPOSE_VOLMOUNT_DEFAULT_FILE)
endif

S2I_CONTEXT ?= gateway

GIT_TAG += $(CIRCLE_TAG)
GIT_TAG += $(shell git describe --tags --exact-match 2>/dev/null)

GIT_BRANCH += $(CIRCLE_BRANCH)
GIT_BRANCH += $(shell git symbolic-ref --short HEAD 2>/dev/null)

S2I_OPTIONS = --env GIT_BRANCH=$(firstword $(GIT_BRANCH)) --env GIT_TAG=$(firstword $(GIT_TAG))

CIRCLE_NODE_INDEX ?= 0
CIRCLE_STAGE ?= build
COMPOSE_PROJECT_NAME ?= apicast_$(CIRCLE_STAGE)_$(CIRCLE_NODE_INDEX)

which = $(shell command -v $(1) 2> /dev/null)

ROVER ?= $(call which, rover)
ifeq ($(ROVER),)
ROVER := lua_modules/bin/rover
endif

CPANM ?= $(call which, cpanm)
CARTON ?= $(firstword $(call which, carton) local/bin/carton)

ifneq ($(CI),true)
S2I_OPTIONS += --copy
endif

export COMPOSE_PROJECT_NAME

.PHONY: benchmark lua_modules

test: ## Run all tests
	$(MAKE) --keep-going busted prove builder-image test-builder-image prove-docker runtime-image test-runtime-image

apicast-source: export IMAGE_NAME ?= apicast-test
apicast-source: ## Create Docker Volume container with APIcast source code
	- docker rm -v -f $(COMPOSE_PROJECT_NAME)-source
	docker create --rm -v /opt/app-root/src --name $(COMPOSE_PROJECT_NAME)-source $(IMAGE_NAME) /bin/true
	docker cp . $(COMPOSE_PROJECT_NAME)-source:/opt/app-root/src

nginx:
	@ ($(NGINX) -V 2>&1) > /dev/null

$(CPANM):
ifeq ($(CPANM),)
	$(error Missing cpanminus. Install it by running `curl -L https://cpanmin.us | perl - App::cpanminus`)
endif

local/bin/carton: $(CPANM)
	$(CPANM) --local-lib ./local --notest Carton

cpan: $(CPANM)
	$(CPANM) --local-lib ./local --notest --installdeps ./gateway

PERL5LIB:=$(PWD)/local/lib/perl5:$(PERL5LIB)
export PERL5LIB

CPANFILE ?= $(PWD)/gateway/cpanfile

$(CPANFILE).snapshot : $(CPANFILE)
	$(CARTON) install --cached

carton: export PERL_CARTON_CPANFILE=$(CPANFILE)
carton: export PERL_CARTON_PATH=$(PWD)/local
carton: $(CARTON) $(CPANFILE).snapshot
carton:
	$(CARTON) install --deployment --cached
	$(CARTON) bundle 2> /dev/null

find-file = $(shell find $(2) -type f -name $(1))

circleci = $(shell circleci tests glob $(1) 2>/dev/null | grep -v examples/scaffold | circleci tests split --split-by=timings 2>/dev/null)

split-tests = $(shell echo $(1) | xargs -n 1 echo | circleci tests split --split-by=timings 2>/dev/null)

BUSTED_PATTERN = "{spec,examples}/**/*_spec.lua"
BUSTED_FILES ?= $(call circleci, $(BUSTED_PATTERN))
busted: $(ROVER) lua_modules ## Test Lua.
	$(ROVER) exec bin/busted $(BUSTED_FILES) $(BUSTED_ARGS)
ifeq ($(CI),true)
	@- luacov
endif

PROVE_PATTERN = "{t,examples}/**/*.t"

prove: HARNESS ?= TAP::Harness
prove: PROVE_FILES ?= $(call circleci, $(PROVE_PATTERN))
prove: export TEST_NGINX_RANDOMIZE=1
prove: $(ROVER) lua_modules nginx ## Test nginx
	$(ROVER) exec script/prove --verbose -j$(NPROC) --harness=$(HARNESS) $(PROVE_FILES)

prove-docker: apicast-source
prove-docker: export IMAGE_NAME ?= apicast-test
prove-docker: ## Test nginx inside docker
	$(DOCKER_COMPOSE) run --rm -T prove | awk '/Result: NOTESTS/ { print "FAIL: NOTESTS"; print; exit 1 }; { print }'

builder-image: PULL_POLICY ?= always
builder-image: ## Build builder image
	$(S2I) build . $(BUILDER_IMAGE) $(IMAGE_NAME) \
		--context-dir=$(S2I_CONTEXT) \
		--pull-policy=$(PULL_POLICY) \
		--runtime-pull-policy=$(PULL_POLICY) \
		--incremental $(S2I_OPTIONS)

runtime-image: PULL_POLICY ?= always
runtime-image: IMAGE_NAME = apicast-runtime-image
runtime-image: ## Build runtime image
	$(S2I) build . $(BUILDER_IMAGE) $(IMAGE_NAME) \
		--context-dir=$(S2I_CONTEXT) \
		--runtime-image=$(RUNTIME_IMAGE) \
		--pull-policy=$(PULL_POLICY) \
		--runtime-pull-policy=$(PULL_POLICY) \
		$(S2I_OPTIONS)

push: ## Push image to the registry
	docker tag $(IMAGE_NAME) $(REGISTRY)/$(IMAGE_NAME)
	docker push $(REGISTRY)/$(IMAGE_NAME)

bash: export IMAGE_NAME ?= apicast-test
bash: export SERVICE = gateway
bash: builder-image apicast-source ## Run bash inside the builder image
	$(DOCKER_COMPOSE) run --user=root --rm --entrypoint=bash $(SERVICE)

dev: export IMAGE_NAME ?= apicast-test
dev: export SERVICE = dev
dev: USER = root
dev: builder-image apicast-source ## Run APIcast inside the container mounted to local volume
	$(DOCKER_COMPOSE) run --user=$(USER) --service-ports --rm --entrypoint=bash $(SERVICE) -i

test-builder-image: export IMAGE_NAME ?= apicast-test
test-builder-image: clean-containers ## Smoke test the builder image. Pass any docker image in IMAGE_NAME parameter.
	$(DOCKER_COMPOSE) --version
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm --user 100001 gateway bin/apicast --test
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm --user 100001 gateway bin/apicast --test --dev
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm --user 100001 gateway bin/apicast --daemon
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm test bash -c 'for i in {1..5}; do curl --fail http://gateway:8090/status/live && break || sleep 1; done'
	$(DOCKER_COMPOSE) logs gateway
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm test curl --fail -X PUT http://gateway:8090/config --data '{"services":[{"id":42}]}'
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm -e THREESCALE_PORTAL_ENDPOINT=http://gateway:8090/config --user 100001 test /tmp/scripts/run -d
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm test curl --fail http://gateway:8090/status/ready
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm test curl --fail -X POST http://gateway:8090/boot
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm -e THREESCALE_PORTAL_ENDPOINT=https://echo-api.3scale.net gateway libexec/boot | grep 'APIcast/'
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm gateway bin/apicast -c http://echo-api.3scale.net -d -b

gateway-logs: export IMAGE_NAME = does-not-matter
gateway-logs:
	$(DOCKER_COMPOSE) logs gateway

test-runtime-image: export IMAGE_NAME = apicast-runtime-image
test-runtime-image: clean-containers ## Smoke test the runtime image. Pass any docker image in IMAGE_NAME parameter.
	$(DOCKER_COMPOSE) run --rm --user 100001 gateway apicast -l -d
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm --user 100002 -e APICAST_CONFIGURATION_LOADER=boot -e THREESCALE_PORTAL_ENDPOINT=https://echo-api.3scale.net gateway bin/apicast -d
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm test sh -c 'sleep 5 && curl --fail http://gateway:8090/status/live'

.docker/lua_modules .docker/local .docker/cpanm .docker/vendor/cache :
	mkdir -p $@

ifeq ($(origin USER),environment)
development: USER := $(shell id -u $(USER))
endif
development: .docker/lua_modules .docker/local .docker/cpanm .docker/vendor/cache
development: ## Run bash inside the development image
	@echo "Running on $(os)"
	- $(DOCKER_COMPOSE) -f $(DEVEL_DOCKER_COMPOSE_FILE) -f $(DEVEL_DOCKER_COMPOSE_VOLMOUNT_FILE) up -d
	@ # https://github.com/moby/moby/issues/33794#issuecomment-312873988 for fixing the terminal width
	$(DOCKER_COMPOSE) -f $(DEVEL_DOCKER_COMPOSE_FILE) -f $(DEVEL_DOCKER_COMPOSE_VOLMOUNT_FILE) exec -e COLUMNS="`tput cols`" -e LINES="`tput lines`" --user $(USER) development bash

stop-development: ## Stop development environment
	- $(DOCKER_COMPOSE) -f $(DEVEL_DOCKER_COMPOSE_FILE) -f $(DEVEL_DOCKER_COMPOSE_VOLMOUNT_FILE) down

rover: $(ROVER)
	@echo $(ROVER)

$(S2I_CONTEXT)/Roverfile.lock : $(S2I_CONTEXT)/Roverfile $(S2I_CONTEXT)/apicast-scm-1.rockspec
	$(ROVER) lock --roverfile=$(S2I_CONTEXT)/Roverfile

lua_modules: $(ROVER) $(S2I_CONTEXT)/Roverfile.lock
	# This variable is to skip issues with openssl 1.1.1
	# https://github.com/wahern/luaossl/issues/175
	EXTRA_CFLAGS="-DHAVE_EVP_KDF_CTX=1" $(ROVER) install --roverfile=$(S2I_CONTEXT)/Roverfile

lua_modules/bin/rover:
	@LUAROCKS_CONFIG=$(S2I_CONTEXT)/config-5.1.lua luarocks install --server=http://luarocks.org/dev lua-rover --tree=lua_modules 1>&2

dependencies: lua_modules carton  ## Install project dependencies

clean-containers: apicast-source
	$(DOCKER_COMPOSE) down --volumes

clean: clean-containers ## Remove all running docker containers and images
	- docker rmi apicast-test apicast-runtime-image --force
	- rm -rf luacov.stats*.out

doc/lua/index.html: $(shell find gateway/src -name '*.lua' 2>/dev/null) | lua_modules $(ROVER)
	$(ROVER) exec ldoc -c doc/config.ld .

doc: doc/lua/index.html ## Generate documentation

lint-schema: apicast-source
	@ docker run --volumes-from ${COMPOSE_PROJECT_NAME}-source --workdir /opt/app-root/src \
		3scale/ajv validate \
		-s gateway/src/apicast/policy/manifest-schema.json \
		$(addprefix -d ,$(shell find gateway/src/apicast/policy -name 'apicast-policy.json'))

node_modules/.bin/markdown-link-check:
	yarn install

test-doc: node_modules/.bin/markdown-link-check
	@find . \( -name node_modules -o -name .git -o -name t \) -prune -o -name "*.md" -print0 | xargs -0 -n1  -I % sh -c 'echo; echo ====================; echo Checking: %; node_modules/.bin/markdown-link-check  %' \;

benchmark: export IMAGE_TAG ?= master
benchmark: export COMPOSE_FILE ?= docker-compose.benchmark.yml
benchmark: export COMPOSE_PROJECT_NAME = apicast-benchmark
benchmark: export WRK_REPORT ?= $(IMAGE_TAG).csv
benchmark: export DURATION ?= 300
benchmark:
	- $(DOCKER_COMPOSE) up --force-recreate -d apicast
	$(DOCKER_COMPOSE) run curl
	## warmup round for $(DURATION)/10 seconds
	DURATION=$$(( $(DURATION) / 10 )) $(DOCKER_COMPOSE) run wrk
	## run the real benchmark for $(DURATION) seconds
	$(DOCKER_COMPOSE) run wrk

# Check http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help: ## Print this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
