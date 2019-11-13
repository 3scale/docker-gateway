# TLS termination policy

This policy adds the support to enable TLS termination with an unique
certificate to the given service.

## Configuration

For this policy `APICAST_HTTPS_PORT` variable need to be defined to be able to
listen in TLS in any port.


### Embedded certificate:

```
{
  "name": "apicast.policy.tls",
  "configuration": {
    "certificates": [
      {
        "certificate": "data:application/pkix-cert;name=one.crt;base64,XXXXXX",
        "certificate_key": "data:application/x-iwork-keynote-sffkey;name=one.key;base64,XXXXX"
      }
    ]
  }
}
```

### Certificate from local filesystem
```
{
  "name": "apicast.policy.tls",
  "configuration": {
    "certificates": [
      {
        "certificate_path": "/home/centos/customCerts/one.crt",
        "certificate_key_path": "/home/centos/customCerts/one.key"
      }
    ]
  }
}
```


## Develop

To get some custom certificates, the following Makefile will help:

```
clean:
	rm *.crt *.key *.pem *.csr

ca: 
	openssl genrsa -out rootCA.key 2048
	openssl req -batch -new -x509 -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.pem

clientcerts:	
	openssl req -subj '/CN=$(DOMAIN)'  -newkey rsa:4096 -nodes \
		-sha256 \
		-days 3650 \
		-keyout $(DOMAIN).key \
		-out $(DOMAIN).csr
	openssl x509 -req -in $(DOMAIN).csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out $(DOMAIN).crt -days 500 -sha256
```

Custom certs for domains can be created using the following commands

```
make clean
make ca
make clientcerts DOMAIN=test.example.com
make clientcerts DOMAIN=testb.example.com
```

Configuration will be like this: 
```
{
  "name": "apicast.policy.tls",
  "configuration": {
    "certificates": [
      {
        "certificate_path": "/home/centos/customCerts/test.example.com.crt",
        "certificate_key_path": "/home/centos/customCerts/test.example.com.key"
      }
    ]
  }
}
```

To test using curl, the custom CA certificate need to be added:

```
curl --resolve test.example.com:1443:172.18.0.3 "https://test.example.com:1443/?user_key=123"  -v --cacert customCerts/rootCA.pem;
```
