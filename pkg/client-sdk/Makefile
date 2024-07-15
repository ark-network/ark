genrest:
	swagger generate client -f ./../../server/api-spec/openapi/swagger/ark/v1/admin.swagger.json -t ./rest/admin --client-package=arkadminrestclient
	swagger generate client -f ./../../server/api-spec/openapi/swagger/ark/v1/service.swagger.json -t ./rest/service --client-package=arkservicerestclient

vet:
	go vet ./...