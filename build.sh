#! /bin/bash

set -e

CGO_ENABLED=0 go build -ldflags "-s -w" -tags 'osusergo,netgo,static_build' -o flubber