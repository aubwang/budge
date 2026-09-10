#!/usr/bin/env sh
set -eu
mkdir -p bin
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "bin/budge-linux-$arch" ./cmd/budge
done
