package permissions_test

import (
	"fmt"
	"testing"

	grpchealth "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/ark-network/ark/server/internal/interface/grpc/permissions"
	"github.com/stretchr/testify/require"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
)

func TestRestrictedMethods(t *testing.T) {
	allMethods := make([]string, 0)
	for _, m := range arkv1.AdminService_ServiceDesc.Methods {
		allMethods = append(allMethods, fmt.Sprintf("/%s/%s", arkv1.AdminService_ServiceDesc.ServiceName, m.MethodName))
	}
	for _, m := range arkv1.WalletService_ServiceDesc.Methods {
		allMethods = append(allMethods, fmt.Sprintf("/%s/%s", arkv1.WalletService_ServiceDesc.ServiceName, m.MethodName))
	}

	allPermissions := permissions.AllPermissionsByMethod()
	for _, method := range allMethods {
		_, ok := allPermissions[method]
		require.True(t, ok, fmt.Sprintf("missing permission for %s", method))
	}
}

func TestWhitelistedMethods(t *testing.T) {
	allMethods := make([]string, 0)
	for _, m := range arkv1.ArkService_ServiceDesc.Methods {
		allMethods = append(allMethods, fmt.Sprintf("/%s/%s", arkv1.ArkService_ServiceDesc.ServiceName, m.MethodName))
	}
	for _, v := range arkv1.WalletInitializerService_ServiceDesc.Methods {
		allMethods = append(allMethods, fmt.Sprintf("/%s/%s", arkv1.WalletInitializerService_ServiceDesc.ServiceName, v.MethodName))
	}
	for _, m := range arkv1.ExplorerService_ServiceDesc.Methods {
		allMethods = append(allMethods, fmt.Sprintf("/%s/%s", arkv1.ExplorerService_ServiceDesc.ServiceName, m.MethodName))
	}
	allMethods = append(allMethods, fmt.Sprintf("/%s/%s", grpchealth.Health_ServiceDesc.ServiceName, "Check"))

	whitelist := permissions.Whitelist()
	for _, m := range allMethods {
		_, ok := whitelist[m]
		require.True(t, ok, fmt.Sprintf("missing %s in whitelist", m))
	}
}
