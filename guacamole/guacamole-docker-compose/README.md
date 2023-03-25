# Guacamole Docker-compose deployment

A bundle of guacamole, MySQL and Caddy for running a production grade Guacamole installation.
This setup is being pre-configure with Keycloak OpenID Connect authentication.

List of services:
 - MySQL
 - Guacamole (web client)
 - Guacd (remote desktop proxy)
 - Caddy (HTTP TLS proxy)

## Prerequisites

- at least 4GB RAM on Docker Host to run all containers
- Docker v1.13+

## Quick Start Guide

 - Configure Keycloak realm and create a client without secret key and with implicit flow enabled
 - Copy `env.example` to `.env` and fill in all empty variables
 - Start docker-compose services:

```bash
 docker-compose up -d
```

 - Initialize the guacamole MySQL database as mentioned at https://guacamole.apache.org/doc/gug/guacamole-docker.html

## Using TLS

This setup supports following types of SSL certificates:

- Email - set environment variable TLS to your email to register Let's Encrypt account and get free automatic SSL certificates.

Example:

```bash
TLS=my@email.com
```

- Internal - set environment variable TLS to "internal" to generate self-signed certificates for dev environments

Example:

```bash
TLS=internal
```

- Custom - set environment variable TLS to "cert.pem key.pem" where cert.pem and key.pem - are paths to your custom certificates (this needs modifying docker-compose with path to your certificates passed as volumes)

Example:

```bash
TLS=cert.pem key.pem
```
