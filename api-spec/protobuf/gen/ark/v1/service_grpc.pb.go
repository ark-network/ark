// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package arkv1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ArkServiceClient is the client API for ArkService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ArkServiceClient interface {
	GetInfo(ctx context.Context, in *GetInfoRequest, opts ...grpc.CallOption) (*GetInfoResponse, error)
	RegisterIntent(ctx context.Context, in *RegisterIntentRequest, opts ...grpc.CallOption) (*RegisterIntentResponse, error)
	SubmitTreeNonces(ctx context.Context, in *SubmitTreeNoncesRequest, opts ...grpc.CallOption) (*SubmitTreeNoncesResponse, error)
	SubmitTreeSignatures(ctx context.Context, in *SubmitTreeSignaturesRequest, opts ...grpc.CallOption) (*SubmitTreeSignaturesResponse, error)
	SubmitSignedForfeitTxs(ctx context.Context, in *SubmitSignedForfeitTxsRequest, opts ...grpc.CallOption) (*SubmitSignedForfeitTxsResponse, error)
	GetBatchEventStream(ctx context.Context, in *GetBatchEventStreamRequest, opts ...grpc.CallOption) (ArkService_GetBatchEventStreamClient, error)
	ConfirmRegistration(ctx context.Context, in *ConfirmRegistrationRequest, opts ...grpc.CallOption) (*ConfirmRegistrationResponse, error)
	RegisterBlindedOutputs(ctx context.Context, in *RegisterBlindedOutputsRequest, opts ...grpc.CallOption) (*RegisterBlindedOutputsResponse, error)
	SubmitTx(ctx context.Context, in *SubmitTxRequest, opts ...grpc.CallOption) (*SubmitTxResponse, error)
	SubmitCheckpointTxs(ctx context.Context, in *SubmitCheckpointTxsRequest, opts ...grpc.CallOption) (*SubmitCheckpointTxsResponse, error)
}

type arkServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewArkServiceClient(cc grpc.ClientConnInterface) ArkServiceClient {
	return &arkServiceClient{cc}
}

func (c *arkServiceClient) GetInfo(ctx context.Context, in *GetInfoRequest, opts ...grpc.CallOption) (*GetInfoResponse, error) {
	out := new(GetInfoResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/GetInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) RegisterIntent(ctx context.Context, in *RegisterIntentRequest, opts ...grpc.CallOption) (*RegisterIntentResponse, error) {
	out := new(RegisterIntentResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/RegisterIntent", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) SubmitTreeNonces(ctx context.Context, in *SubmitTreeNoncesRequest, opts ...grpc.CallOption) (*SubmitTreeNoncesResponse, error) {
	out := new(SubmitTreeNoncesResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/SubmitTreeNonces", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) SubmitTreeSignatures(ctx context.Context, in *SubmitTreeSignaturesRequest, opts ...grpc.CallOption) (*SubmitTreeSignaturesResponse, error) {
	out := new(SubmitTreeSignaturesResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/SubmitTreeSignatures", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) SubmitSignedForfeitTxs(ctx context.Context, in *SubmitSignedForfeitTxsRequest, opts ...grpc.CallOption) (*SubmitSignedForfeitTxsResponse, error) {
	out := new(SubmitSignedForfeitTxsResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/SubmitSignedForfeitTxs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) GetBatchEventStream(ctx context.Context, in *GetBatchEventStreamRequest, opts ...grpc.CallOption) (ArkService_GetBatchEventStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &ArkService_ServiceDesc.Streams[0], "/ark.v1.ArkService/GetBatchEventStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &arkServiceGetBatchEventStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type ArkService_GetBatchEventStreamClient interface {
	Recv() (*GetBatchEventStreamResponse, error)
	grpc.ClientStream
}

type arkServiceGetBatchEventStreamClient struct {
	grpc.ClientStream
}

func (x *arkServiceGetBatchEventStreamClient) Recv() (*GetBatchEventStreamResponse, error) {
	m := new(GetBatchEventStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *arkServiceClient) ConfirmRegistration(ctx context.Context, in *ConfirmRegistrationRequest, opts ...grpc.CallOption) (*ConfirmRegistrationResponse, error) {
	out := new(ConfirmRegistrationResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/ConfirmRegistration", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) RegisterBlindedOutputs(ctx context.Context, in *RegisterBlindedOutputsRequest, opts ...grpc.CallOption) (*RegisterBlindedOutputsResponse, error) {
	out := new(RegisterBlindedOutputsResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/RegisterBlindedOutputs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) SubmitTx(ctx context.Context, in *SubmitTxRequest, opts ...grpc.CallOption) (*SubmitTxResponse, error) {
	out := new(SubmitTxResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/SubmitTx", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) SubmitCheckpointTxs(ctx context.Context, in *SubmitCheckpointTxsRequest, opts ...grpc.CallOption) (*SubmitCheckpointTxsResponse, error) {
	out := new(SubmitCheckpointTxsResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/SubmitCheckpointTxs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ArkServiceServer is the server API for ArkService service.
// All implementations should embed UnimplementedArkServiceServer
// for forward compatibility
type ArkServiceServer interface {
	GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error)
	RegisterIntent(context.Context, *RegisterIntentRequest) (*RegisterIntentResponse, error)
	SubmitTreeNonces(context.Context, *SubmitTreeNoncesRequest) (*SubmitTreeNoncesResponse, error)
	SubmitTreeSignatures(context.Context, *SubmitTreeSignaturesRequest) (*SubmitTreeSignaturesResponse, error)
	SubmitSignedForfeitTxs(context.Context, *SubmitSignedForfeitTxsRequest) (*SubmitSignedForfeitTxsResponse, error)
	GetBatchEventStream(*GetBatchEventStreamRequest, ArkService_GetBatchEventStreamServer) error
	ConfirmRegistration(context.Context, *ConfirmRegistrationRequest) (*ConfirmRegistrationResponse, error)
	RegisterBlindedOutputs(context.Context, *RegisterBlindedOutputsRequest) (*RegisterBlindedOutputsResponse, error)
	SubmitTx(context.Context, *SubmitTxRequest) (*SubmitTxResponse, error)
	SubmitCheckpointTxs(context.Context, *SubmitCheckpointTxsRequest) (*SubmitCheckpointTxsResponse, error)
}

// UnimplementedArkServiceServer should be embedded to have forward compatible implementations.
type UnimplementedArkServiceServer struct {
}

func (UnimplementedArkServiceServer) GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetInfo not implemented")
}
func (UnimplementedArkServiceServer) RegisterIntent(context.Context, *RegisterIntentRequest) (*RegisterIntentResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterIntent not implemented")
}
func (UnimplementedArkServiceServer) SubmitTreeNonces(context.Context, *SubmitTreeNoncesRequest) (*SubmitTreeNoncesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitTreeNonces not implemented")
}
func (UnimplementedArkServiceServer) SubmitTreeSignatures(context.Context, *SubmitTreeSignaturesRequest) (*SubmitTreeSignaturesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitTreeSignatures not implemented")
}
func (UnimplementedArkServiceServer) SubmitSignedForfeitTxs(context.Context, *SubmitSignedForfeitTxsRequest) (*SubmitSignedForfeitTxsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitSignedForfeitTxs not implemented")
}
func (UnimplementedArkServiceServer) GetBatchEventStream(*GetBatchEventStreamRequest, ArkService_GetBatchEventStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method GetBatchEventStream not implemented")
}
func (UnimplementedArkServiceServer) ConfirmRegistration(context.Context, *ConfirmRegistrationRequest) (*ConfirmRegistrationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ConfirmRegistration not implemented")
}
func (UnimplementedArkServiceServer) RegisterBlindedOutputs(context.Context, *RegisterBlindedOutputsRequest) (*RegisterBlindedOutputsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterBlindedOutputs not implemented")
}
func (UnimplementedArkServiceServer) SubmitTx(context.Context, *SubmitTxRequest) (*SubmitTxResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitTx not implemented")
}
func (UnimplementedArkServiceServer) SubmitCheckpointTxs(context.Context, *SubmitCheckpointTxsRequest) (*SubmitCheckpointTxsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitCheckpointTxs not implemented")
}

// UnsafeArkServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ArkServiceServer will
// result in compilation errors.
type UnsafeArkServiceServer interface {
	mustEmbedUnimplementedArkServiceServer()
}

func RegisterArkServiceServer(s grpc.ServiceRegistrar, srv ArkServiceServer) {
	s.RegisterService(&ArkService_ServiceDesc, srv)
}

func _ArkService_GetInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).GetInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/GetInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).GetInfo(ctx, req.(*GetInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_RegisterIntent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterIntentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).RegisterIntent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/RegisterIntent",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).RegisterIntent(ctx, req.(*RegisterIntentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_SubmitTreeNonces_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SubmitTreeNoncesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).SubmitTreeNonces(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/SubmitTreeNonces",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).SubmitTreeNonces(ctx, req.(*SubmitTreeNoncesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_SubmitTreeSignatures_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SubmitTreeSignaturesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).SubmitTreeSignatures(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/SubmitTreeSignatures",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).SubmitTreeSignatures(ctx, req.(*SubmitTreeSignaturesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_SubmitSignedForfeitTxs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SubmitSignedForfeitTxsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).SubmitSignedForfeitTxs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/SubmitSignedForfeitTxs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).SubmitSignedForfeitTxs(ctx, req.(*SubmitSignedForfeitTxsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_GetBatchEventStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetBatchEventStreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ArkServiceServer).GetBatchEventStream(m, &arkServiceGetBatchEventStreamServer{stream})
}

type ArkService_GetBatchEventStreamServer interface {
	Send(*GetBatchEventStreamResponse) error
	grpc.ServerStream
}

type arkServiceGetBatchEventStreamServer struct {
	grpc.ServerStream
}

func (x *arkServiceGetBatchEventStreamServer) Send(m *GetBatchEventStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _ArkService_ConfirmRegistration_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ConfirmRegistrationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).ConfirmRegistration(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/ConfirmRegistration",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).ConfirmRegistration(ctx, req.(*ConfirmRegistrationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_RegisterBlindedOutputs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterBlindedOutputsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).RegisterBlindedOutputs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/RegisterBlindedOutputs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).RegisterBlindedOutputs(ctx, req.(*RegisterBlindedOutputsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_SubmitTx_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SubmitTxRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).SubmitTx(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/SubmitTx",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).SubmitTx(ctx, req.(*SubmitTxRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_SubmitCheckpointTxs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SubmitCheckpointTxsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).SubmitCheckpointTxs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/SubmitCheckpointTxs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).SubmitCheckpointTxs(ctx, req.(*SubmitCheckpointTxsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ArkService_ServiceDesc is the grpc.ServiceDesc for ArkService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ArkService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "ark.v1.ArkService",
	HandlerType: (*ArkServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetInfo",
			Handler:    _ArkService_GetInfo_Handler,
		},
		{
			MethodName: "RegisterIntent",
			Handler:    _ArkService_RegisterIntent_Handler,
		},
		{
			MethodName: "SubmitTreeNonces",
			Handler:    _ArkService_SubmitTreeNonces_Handler,
		},
		{
			MethodName: "SubmitTreeSignatures",
			Handler:    _ArkService_SubmitTreeSignatures_Handler,
		},
		{
			MethodName: "SubmitSignedForfeitTxs",
			Handler:    _ArkService_SubmitSignedForfeitTxs_Handler,
		},
		{
			MethodName: "ConfirmRegistration",
			Handler:    _ArkService_ConfirmRegistration_Handler,
		},
		{
			MethodName: "RegisterBlindedOutputs",
			Handler:    _ArkService_RegisterBlindedOutputs_Handler,
		},
		{
			MethodName: "SubmitTx",
			Handler:    _ArkService_SubmitTx_Handler,
		},
		{
			MethodName: "SubmitCheckpointTxs",
			Handler:    _ArkService_SubmitCheckpointTxs_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetBatchEventStream",
			Handler:       _ArkService_GetBatchEventStream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "ark/v1/service.proto",
}
