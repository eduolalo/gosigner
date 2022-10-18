#!/usr/bin/env bash

# limpiar caché
go clean -testcache

# Ejecución de los tests completos
go test ./... -v -cover
