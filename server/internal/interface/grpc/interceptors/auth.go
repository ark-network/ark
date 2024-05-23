package interceptors

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	arkv1 "github.com/ark-network/ark/api-spec/protobuf/gen/ark/v1"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func unaryAuthenticator(user, pass string) grpc.UnaryServerInterceptor {
	adminToken := fmt.Sprintf("%s:%s", user, pass)
	adminTokenEncoded := base64.StdEncoding.EncodeToString([]byte(adminToken))

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// whitelist the ArkService
		if strings.Contains(info.FullMethod, arkv1.ArkService_ServiceDesc.ServiceName) {
			return handler(ctx, req)
		}

		token, err := grpc_auth.AuthFromMD(ctx, "basic")
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "no basic header found: %v", err)
		}

		if token != adminTokenEncoded {
			return nil, status.Errorf(codes.Unauthenticated, "invalid auth credentials: %v", err)
		}

		return handler(ctx, req)
	}
}
