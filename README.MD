Please use the following steps to test mock-server

- install golang 1.22 or later
- clone code localy
- update appsettings.json to change port, endpoints, issuer and other parameters
- if you need TLS support, enable it in the config and generate certificate and key by running the following command: openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
- run the code: go run server.go

