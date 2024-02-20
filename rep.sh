#!/bin/bash
go fmt rep.go && go build -ldflags '-s -w' -o rep rep.go && echo ok
