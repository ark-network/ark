.PHONY: genrest test vet

## genrest: compiles rest client from stub with https://github.com/go-swagger/go-swagger
genrest:
	@echo "Generating rest client from stub..."
	@swagger generate client -f ../../server/api-spec/openapi/swagger/ark/v1/service.swagger.json -t ./client/rest/service --client-package=arkservice

## test: runs unit tests
test:
	@echo "Running unit tests..."
	@go test -v -count=1 -race ./...

## vet: code analysis
vet:
	@echo "Running code analysis..."
	@go vet ./...