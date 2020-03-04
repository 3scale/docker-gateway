# gRPC on APIcast

APIcast 3.8 fully supports the HTTP/2 protocol. This enables APIcast to handle
gRPC connections end-to-end, taking care of APIcast authentication, headers
modification, and so on.

HTTP/2 is only enabled in the Transport Layer Security (TLS) port. It is not
enabled in the plaintext port. It is only enabled in TLS to support both HTTP
1.1 and 1.1 and HTTP2 protocols are supported. Within the TLS hello exchanges,
the Application-Layer Protocol Negotiation (ALPN) uses the appropriate protocol.
HTTP2 always takes precedence.

Use headers authentication or OpenID, JSON Web Tokens (JWT), for transparency of
the gRPC endpoints and to make it easier to add in the gRPC clients.

The GRPC endpoint server should also listen in TLS, MTLS can be enabled or not,
but the endpoint should finish TLS connections to be able to work as expected.

In APIcast, for full gRPC traffic, enable the gRPC policy in the given service.
The protocol used will then be full HTTP/2. This is because NGINX directives do
not support ALPN.

### Minimal APIcast configuration

```
    {
      "services": [
        {
          "id": 200,
          "backend_version":  1,
          "backend_authentication_type": "service_token",
          "backend_authentication_value": "token-value",
          "proxy": {
            "credentials_location": "headers",
            "hosts": [
              "apicast-service"
            ],
            "api_backend": "https://grpc-service:443",
            "proxy_rules": [
              {
                "pattern": "/",
                "http_method": "GET",
                "metric_system_name": "hits",
                "delta": 1
              },
              {
                "pattern": "/",
                "http_method": "POST",
                "metric_system_name": "hits",
                "delta": 1
              }
            ],
            "policy_chain": [
              {
                "name": "apicast.policy.tls",
                "configuration": {
                  "certificates": [
                    {
                      "certificate_path": "/gateway/apicast-service.crt",
                      "certificate_key_path": "/gateway/apicast-service.key"
                    }
                  ]
                }
              },
              {
                "name": "apicast.policy.grpc"
              },
              {
                "name": "apicast.policy.apicast"
              }
            ]
          }
        }
      ]
    }
```

### gRPC client information

- Server TLS listener

Example using golang:

```
	creds, err := credentials.NewServerTLSFromFile(*cert, *key)
	if err != nil {
		log.Fatalf("Failed to setup TLS: %v", err)
	}

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer(grpc.Creds(creds))

```

Client header metadata using golang:

This snippet adds metadata as headers to send the credentials in the header,
making it easier to read.

```

	md := metadata.Pairs("user_key", *user_key)
	ctx := metadata.NewOutgoingContext(context.Background(), md)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
```
