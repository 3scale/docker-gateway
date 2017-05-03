IMAGE_NAME ?= apicast-s2i-example

ssl:
	mkdir $@
ssl/resty-auto-ssl-fallback.key: ssl
	openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
		-subj '/CN=sni-support-required-for-valid-ssl' \
		-keyout $@ \
		-out $(patsubst %.key,%.crt,$@)
build: ssl/resty-auto-ssl-fallback.key
	s2i build . quay.io/3scale/apicast:master-builder $(IMAGE_NAME) --environment-file=.env --assemble-user=root

test:
	docker run $(IMAGE_NAME)

bash: USER = 100001
bash:
	exec docker run -v $(PWD)/storage:/tmp/resty-auto-ssl --user=$(USER) -p 8443:8443 -p 8080:8080 -p 8999:8999 -it $(IMAGE_NAME) bash

