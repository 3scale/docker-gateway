.DEFAULT_GOAL := help

DOCKER_COMPOSE = docker-compose
S2I = s2i
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

S2I_CONTEXT ?= gateway

CIRCLE_NODE_INDEX ?= 0
CIRCLE_STAGE ?= build
COMPOSE_PROJECT_NAME ?= apicast_$(CIRCLE_STAGE)_$(CIRCLE_NODE_INDEX)

ROVER ?= $(shell which rover 2> /dev/null)
ifeq ($(ROVER),)
ROVER := lua_modules/bin/rover
endif

CPANM ?= $(shell command -v cpanm 2> /dev/null)

export COMPOSE_PROJECT_NAME

test: ## Run all tests
	$(MAKE) --keep-going busted prove builder-image test-builder-image prove-docker runtime-image test-runtime-image

apicast-source: export IMAGE_NAME ?= apicast-test
apicast-source: ## Create Docker Volume container with APIcast source code
	- docker rm -v -f $(COMPOSE_PROJECT_NAME)-source
	docker create --rm -v /opt/app-root/src --name $(COMPOSE_PROJECT_NAME)-source $(IMAGE_NAME) /bin/true
	docker cp . $(COMPOSE_PROJECT_NAME)-source:/opt/app-root/src


busted: dependencies $(ROVER) ## Test Lua.
	@$(ROVER) exec bin/busted
	@- luacov

nginx:
	@ ($(NGINX) -V 2>&1) > /dev/null

cpan:
ifeq ($(CPANM),)
	$(error Missing cpanminus. Install it by running `curl -L https://cpanmin.us | perl - App::cpanminus`)
endif
	$(CPANM) --notest --installdeps ./gateway

prove: HARNESS ?= TAP::Harness
prove: export TEST_NGINX_RANDOMIZE=1
prove: $(ROVER) nginx cpan ## Test nginx
	$(ROVER) exec prove -j$(NPROC) --harness=$(HARNESS) 2>&1 | awk '/found ONLY/ { print "FAIL: because found ONLY in test"; print; exit 1 }; { print }'

prove-docker: apicast-source
prove-docker: export IMAGE_NAME = apicast-test
prove-docker: ## Test nginx inside docker
	$(DOCKER_COMPOSE) run --rm -T prove | awk '/Result: NOTESTS/ { print "FAIL: NOTESTS"; print; exit 1 }; { print }'

builder-image: ## Build builder image
	$(S2I) build . $(BUILDER_IMAGE) $(IMAGE_NAME) --context-dir=$(S2I_CONTEXT) --copy --incremental

runtime-image: PULL_POLICY ?= always
runtime-image: IMAGE_NAME = apicast-runtime-test
runtime-image: ## Build runtime image
	$(S2I) build . $(BUILDER_IMAGE) $(IMAGE_NAME) --context-dir=$(S2I_CONTEXT) --runtime-image=$(RUNTIME_IMAGE) --pull-policy=$(PULL_POLICY) --runtime-pull-policy=$(PULL_POLICY)

push: ## Push image to the registry
	docker tag $(IMAGE_NAME) $(REGISTRY)/$(IMAGE_NAME)
	docker push $(REGISTRY)/$(IMAGE_NAME)

bash: export IMAGE_NAME = apicast-test
bash: export SERVICE = gateway
bash: builder-image apicast-source ## Run bash inside the builder image
	$(DOCKER_COMPOSE) run --user=root --rm --entrypoint=bash $(SERVICE)

dev: export IMAGE_NAME = apicast-test
dev: export SERVICE = dev
dev: USER = root
dev: builder-image apicast-source ## Run APIcast inside the container mounted to local volume
	$(DOCKER_COMPOSE) run --user=$(USER) --service-ports --rm --entrypoint=bash $(SERVICE) -i
test-builder-image: export IMAGE_NAME = apicast-test
test-builder-image: builder-image clean-containers ## Smoke test the builder image. Pass any docker image in IMAGE_NAME parameter.
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

test-runtime-image: export IMAGE_NAME = apicast-runtime-test
test-runtime-image: runtime-image clean-containers ## Smoke test the runtime image. Pass any docker image in IMAGE_NAME parameter.
	$(DOCKER_COMPOSE) run --rm --user 100001 gateway apicast -d
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm --user 100002 -e APICAST_CONFIGURATION_LOADER=boot -e THREESCALE_PORTAL_ENDPOINT=https://echo-api.3scale.net gateway bin/apicast -d
	@echo -e $(SEPARATOR)
	$(DOCKER_COMPOSE) run --rm test sh -c 'sleep 5 && curl --fail http://gateway:8090/status/live'

build-development:
	docker build -f $(DEVEL_DOCKERFILE) -t $(DEVEL_IMAGE) .

development: build-development ## Run bash inside the development image
	$(DOCKER_COMPOSE) -f $(DEVEL_DOCKER_COMPOSE_FILE) run --rm development

rover: $(ROVER)
	@echo $(ROVER)

dependencies: $(ROVER)
	$(ROVER) install --roverfile=$(S2I_CONTEXT)/Roverfile

lua_modules/bin/rover:
	@LUAROCKS_CONFIG=$(S2I_CONTEXT)/config-5.1.lua luarocks install --server=http://luarocks.org/dev lua-rover --tree lua_modules 1>&2

clean-containers: apicast-source
	$(DOCKER_COMPOSE) down --volumes

clean: clean-containers ## Remove all running docker containers and images
	- docker rmi apicast-test apicast-runtime-test --force

doc/lua/index.html: $(shell find gateway/src -name '*.lua') | dependencies $(ROVER)
	$(ROVER) exec ldoc -c doc/config.ld .

doc: doc/lua/index.html ## Generate documentation

lint-schema: apicast-source
	@ docker run --volumes-from ${COMPOSE_PROJECT_NAME}-source --workdir /opt/app-root/src \
	    3scale/ajv validate \
		-s /usr/local/lib/node_modules/ajv-cli/node_modules/ajv/lib/refs/json-schema-draft-07.json \
		$(addprefix -d ,$(shell find gateway/src/apicast/policy -name 'schema.json'))
	@ docker run --volumes-from ${COMPOSE_PROJECT_NAME}-source --workdir /opt/app-root/src \
		3scale/ajv validate \
		-s gateway/src/apicast/policy/manifest-schema.json \
		$(addprefix -d ,$(shell find gateway/src/apicast/policy -name 'manifest.json'))

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
