PRJ=cryptopals

all:
	@cat Makefile | more

# Clear everything (build cache, module cache, and test cache):
clean-cache:
	go clean -cache -modcache -testcache

run:
	@go run $$(find . -maxdepth 1 -name '*.go' ! -name '*_test.go' | sort)

.PHONY: test watch coverage vulncheck lint
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

test:
	go test -v *.go

watch:
	reflex -r '\.go$$' -- sh -c "go test -v ./..."

coverage:
	go test -coverprofile=coverage.out ./...
	#go tool cover -func=coverage.out
	#cat coverage.out

init:
	go mod init github.com/drio/$(PRJ)
	go mod tidy


lint:
	golangci-lint run --fix .


