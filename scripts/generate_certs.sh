#!/bin/bash
mkdir -p certs && cd certs
openssl genrsa -out ca.key 2048 && openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.pem -subj "/CN=MAS-CA"
openssl genrsa -out server.key 2048 && openssl req -new -key server.key -out server.csr -subj "/CN=rabbitmq" && openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365
openssl genrsa -out client.key 2048 && openssl req -new -key client.key -out client.csr -subj "/CN=mas-agents" && openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 365
echo "✅ Certificats générés dans certs/"
