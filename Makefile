PROJECT=github.com/openprovider/crypto
RELEASE?=v0.2.2

all: test lint

GO_PACKAGES=$(shell go list $(PROJECT)/...)

test:
	@echo "+ $@"
	@go list -f '{{if len .TestGoFiles}}"go test -v -race -cover {{.Dir}}"{{end}}' $(GO_PACKAGES) | xargs -L 1 sh -c

bench:
	@echo "+ $@"
	@go list -f '{{if len .TestGoFiles}}"go test -benchmem -bench . {{.Dir}}"{{end}}' $(GO_PACKAGES) | xargs -L 1 sh -c

fmt:
	@echo "+ $@"
	@go list -f '"gofmt -w -s -l {{.Dir}}"' ${GO_PACKAGES} | xargs -L 1 sh -c

lint: bootstrap
	@echo "+ $@"
	@golangci-lint run --enable-all ./...

cover:
	@echo "+ $@"
	@> coverage.txt
	@go list -f '{{if len .TestGoFiles}}"go test -coverprofile={{.Dir}}/.coverprofile {{.ImportPath}} && cat {{.Dir}}/.coverprofile  >> coverage.txt"{{end}}' $(GO_PACKAGES) | xargs -L 1 sh -c

HAS_LINT := $(shell command -v golangci-lint;)

bootstrap:
ifndef HAS_LINT
	go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
endif

.PHONY: all \
	test \
	bench \
	fmt \
	lint \
	cover \
	bootstrap
