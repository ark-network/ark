#!/bin/bash

set -e

go build -buildmode=c-shared -o libark.so ark_sdk_covenantless_c.go
