#!/bin/bash

### get VERSIONSTRING
VERSIONSTRING="$(git describe --tags --exact-match || git rev-parse --short HEAD)"

echo "Building version ${VERSIONSTRING} of HMAC File Server ..."

### Compile and link statically
CGO_ENABLED=0 GOOS=linux go build -a -ldflags "-extldflags '-static' -w -s -X main.versionString=${VERSIONSTRING}" hmac-file-server.go
