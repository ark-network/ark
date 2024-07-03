test:
	go test -v ./...

genrest:
	swagger generate client -f ./../server/api-spec/openapi/swagger/ark/v1/admin.swagger.json -t client-sdk/rest/admin --client-package=client
	swagger generate client -f ./../server/api-spec/openapi/swagger/ark/v1/service.swagger.json -t client-sdk/rest/service --client-package=client