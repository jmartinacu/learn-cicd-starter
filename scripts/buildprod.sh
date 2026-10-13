#!/bin/bash

CGO_ENABLED=0 GOOS=linux GOARCH="${1:-amd64}" go build -o notely
