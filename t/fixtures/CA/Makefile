all: client.key client.crt server.key server.crt ca-bundle.crt:

EXPIRATION := 87600h # 10 years 

clean:
	rm *.crt *.key

# http://smallstep.com
root-ca.crt root-ca.key:
	step certificate create root-ca root-ca.crt root-ca.key --profile root-ca \
		--no-password --insecure --not-after=${EXPIRATION}

intermediate-ca.crt intermediate-ca.key: root-ca.crt root-ca.key
	step certificate create intermediate-ca intermediate-ca.crt intermediate-ca.key \
		--profile intermediate-ca --ca ./root-ca.crt --ca-key ./root-ca.key \
		--no-password --insecure --not-after=${EXPIRATION}

ca-bundle.crt: intermediate-ca.crt root-ca.crt
	step certificate bundle intermediate-ca.crt root-ca.crt $@

server.crt server.key: intermediate-ca.crt intermediate-ca.key
	step certificate create server server.crt server.key --profile leaf \
		--ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key \
		--san localhost --san test --no-password --insecure --not-after=${EXPIRATION}

client.crt client.key: intermediate-ca.crt intermediate-ca.key
	step certificate create client client.crt client.key --profile leaf \
		--ca ./intermediate-ca.crt --ca-key ./intermediate-ca.key \
		--no-password --insecure --not-after=${EXPIRATION}
