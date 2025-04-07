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
	GetBoardingAddress(ctx context.Context, in *GetBoardingAddressRequest, opts ...grpc.CallOption) (*GetBoardingAddressResponse, error)
	RegisterInputsForNextRound(ctx context.Context, in *RegisterInputsForNextRoundRequest, opts ...grpc.CallOption) (*RegisterInputsForNextRoundResponse, error)
	RegisterOutputsForNextRound(ctx context.Context, in *RegisterOutputsForNextRoundRequest, opts ...grpc.CallOption) (*RegisterOutputsForNextRoundResponse, error)
	SubmitTreeNonces(ctx context.Context, in *SubmitTreeNoncesRequest, opts ...grpc.CallOption) (*SubmitTreeNoncesResponse, error)
	SubmitTreeSignatures(ctx context.Context, in *SubmitTreeSignaturesRequest, opts ...grpc.CallOption) (*SubmitTreeSignaturesResponse, error)
	SubmitSignedForfeitTxs(ctx context.Context, in *SubmitSignedForfeitTxsRequest, opts ...grpc.CallOption) (*SubmitSignedForfeitTxsResponse, error)
	GetEventStream(ctx context.Context, in *GetEventStreamRequest, opts ...grpc.CallOption) (ArkService_GetEventStreamClient, error)
	Ping(ctx context.Context, in *PingRequest, opts ...grpc.CallOption) (*PingResponse, error)
	SubmitRedeemTx(ctx context.Context, in *SubmitRedeemTxRequest, opts ...grpc.CallOption) (*SubmitRedeemTxResponse, error)
	GetTransactionsStream(ctx context.Context, in *GetTransactionsStreamRequest, opts ...grpc.CallOption) (ArkService_GetTransactionsStreamClient, error)
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

func (c *arkServiceClient) GetBoardingAddress(ctx context.Context, in *GetBoardingAddressRequest, opts ...grpc.CallOption) (*GetBoardingAddressResponse, error) {
	out := new(GetBoardingAddressResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/GetBoardingAddress", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) RegisterInputsForNextRound(ctx context.Context, in *RegisterInputsForNextRoundRequest, opts ...grpc.CallOption) (*RegisterInputsForNextRoundResponse, error) {
	out := new(RegisterInputsForNextRoundResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/RegisterInputsForNextRound", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) RegisterOutputsForNextRound(ctx context.Context, in *RegisterOutputsForNextRoundRequest, opts ...grpc.CallOption) (*RegisterOutputsForNextRoundResponse, error) {
	out := new(RegisterOutputsForNextRoundResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/RegisterOutputsForNextRound", in, out, opts...)
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

func (c *arkServiceClient) GetEventStream(ctx context.Context, in *GetEventStreamRequest, opts ...grpc.CallOption) (ArkService_GetEventStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &ArkService_ServiceDesc.Streams[0], "/ark.v1.ArkService/GetEventStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &arkServiceGetEventStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type ArkService_GetEventStreamClient interface {
	Recv() (*GetEventStreamResponse, error)
	grpc.ClientStream
}

type arkServiceGetEventStreamClient struct {
	grpc.ClientStream
}

func (x *arkServiceGetEventStreamClient) Recv() (*GetEventStreamResponse, error) {
	m := new(GetEventStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *arkServiceClient) Ping(ctx context.Context, in *PingRequest, opts ...grpc.CallOption) (*PingResponse, error) {
	out := new(PingResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/Ping", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) SubmitRedeemTx(ctx context.Context, in *SubmitRedeemTxRequest, opts ...grpc.CallOption) (*SubmitRedeemTxResponse, error) {
	out := new(SubmitRedeemTxResponse)
	err := c.cc.Invoke(ctx, "/ark.v1.ArkService/SubmitRedeemTx", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *arkServiceClient) GetTransactionsStream(ctx context.Context, in *GetTransactionsStreamRequest, opts ...grpc.CallOption) (ArkService_GetTransactionsStreamClient, error) {
	stream, err := c.cc.NewStream(ctx, &ArkService_ServiceDesc.Streams[1], "/ark.v1.ArkService/GetTransactionsStream", opts...)
	if err != nil {
		return nil, err
	}
	x := &arkServiceGetTransactionsStreamClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type ArkService_GetTransactionsStreamClient interface {
	Recv() (*GetTransactionsStreamResponse, error)
	grpc.ClientStream
}

type arkServiceGetTransactionsStreamClient struct {
	grpc.ClientStream
}

func (x *arkServiceGetTransactionsStreamClient) Recv() (*GetTransactionsStreamResponse, error) {
	m := new(GetTransactionsStreamResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ArkServiceServer is the server API for ArkService service.
// All implementations should embed UnimplementedArkServiceServer
// for forward compatibility
type ArkServiceServer interface {
	GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error)
	GetBoardingAddress(context.Context, *GetBoardingAddressRequest) (*GetBoardingAddressResponse, error)
	RegisterInputsForNextRound(context.Context, *RegisterInputsForNextRoundRequest) (*RegisterInputsForNextRoundResponse, error)
	RegisterOutputsForNextRound(context.Context, *RegisterOutputsForNextRoundRequest) (*RegisterOutputsForNextRoundResponse, error)
	SubmitTreeNonces(context.Context, *SubmitTreeNoncesRequest) (*SubmitTreeNoncesResponse, error)
	SubmitTreeSignatures(context.Context, *SubmitTreeSignaturesRequest) (*SubmitTreeSignaturesResponse, error)
	SubmitSignedForfeitTxs(context.Context, *SubmitSignedForfeitTxsRequest) (*SubmitSignedForfeitTxsResponse, error)
	GetEventStream(*GetEventStreamRequest, ArkService_GetEventStreamServer) error
	Ping(context.Context, *PingRequest) (*PingResponse, error)
	SubmitRedeemTx(context.Context, *SubmitRedeemTxRequest) (*SubmitRedeemTxResponse, error)
	GetTransactionsStream(*GetTransactionsStreamRequest, ArkService_GetTransactionsStreamServer) error
}

// UnimplementedArkServiceServer should be embedded to have forward compatible implementations.
type UnimplementedArkServiceServer struct {
}

func (UnimplementedArkServiceServer) GetInfo(context.Context, *GetInfoRequest) (*GetInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetInfo not implemented")
}
func (UnimplementedArkServiceServer) GetBoardingAddress(context.Context, *GetBoardingAddressRequest) (*GetBoardingAddressResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetBoardingAddress not implemented")
}
func (UnimplementedArkServiceServer) RegisterInputsForNextRound(context.Context, *RegisterInputsForNextRoundRequest) (*RegisterInputsForNextRoundResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterInputsForNextRound not implemented")
}
func (UnimplementedArkServiceServer) RegisterOutputsForNextRound(context.Context, *RegisterOutputsForNextRoundRequest) (*RegisterOutputsForNextRoundResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterOutputsForNextRound not implemented")
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
func (UnimplementedArkServiceServer) GetEventStream(*GetEventStreamRequest, ArkService_GetEventStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method GetEventStream not implemented")
}
func (UnimplementedArkServiceServer) Ping(context.Context, *PingRequest) (*PingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Ping not implemented")
}
func (UnimplementedArkServiceServer) SubmitRedeemTx(context.Context, *SubmitRedeemTxRequest) (*SubmitRedeemTxResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SubmitRedeemTx not implemented")
}
func (UnimplementedArkServiceServer) GetTransactionsStream(*GetTransactionsStreamRequest, ArkService_GetTransactionsStreamServer) error {
	return status.Errorf(codes.Unimplemented, "method GetTransactionsStream not implemented")
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

func _ArkService_GetBoardingAddress_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBoardingAddressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).GetBoardingAddress(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/GetBoardingAddress",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).GetBoardingAddress(ctx, req.(*GetBoardingAddressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_RegisterInputsForNextRound_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterInputsForNextRoundRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).RegisterInputsForNextRound(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/RegisterInputsForNextRound",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).RegisterInputsForNextRound(ctx, req.(*RegisterInputsForNextRoundRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_RegisterOutputsForNextRound_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterOutputsForNextRoundRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).RegisterOutputsForNextRound(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/RegisterOutputsForNextRound",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).RegisterOutputsForNextRound(ctx, req.(*RegisterOutputsForNextRoundRequest))
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

func _ArkService_GetEventStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetEventStreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ArkServiceServer).GetEventStream(m, &arkServiceGetEventStreamServer{stream})
}

type ArkService_GetEventStreamServer interface {
	Send(*GetEventStreamResponse) error
	grpc.ServerStream
}

type arkServiceGetEventStreamServer struct {
	grpc.ServerStream
}

func (x *arkServiceGetEventStreamServer) Send(m *GetEventStreamResponse) error {
	return x.ServerStream.SendMsg(m)
}

func _ArkService_Ping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).Ping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/Ping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).Ping(ctx, req.(*PingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_SubmitRedeemTx_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SubmitRedeemTxRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ArkServiceServer).SubmitRedeemTx(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ark.v1.ArkService/SubmitRedeemTx",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ArkServiceServer).SubmitRedeemTx(ctx, req.(*SubmitRedeemTxRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ArkService_GetTransactionsStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(GetTransactionsStreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ArkServiceServer).GetTransactionsStream(m, &arkServiceGetTransactionsStreamServer{stream})
}

type ArkService_GetTransactionsStreamServer interface {
	Send(*GetTransactionsStreamResponse) error
	grpc.ServerStream
}

type arkServiceGetTransactionsStreamServer struct {
	grpc.ServerStream
}

func (x *arkServiceGetTransactionsStreamServer) Send(m *GetTransactionsStreamResponse) error {
	return x.ServerStream.SendMsg(m)
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
			MethodName: "GetBoardingAddress",
			Handler:    _ArkService_GetBoardingAddress_Handler,
		},
		{
			MethodName: "RegisterInputsForNextRound",
			Handler:    _ArkService_RegisterInputsForNextRound_Handler,
		},
		{
			MethodName: "RegisterOutputsForNextRound",
			Handler:    _ArkService_RegisterOutputsForNextRound_Handler,
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
			MethodName: "Ping",
			Handler:    _ArkService_Ping_Handler,
		},
		{
			MethodName: "SubmitRedeemTx",
			Handler:    _ArkService_SubmitRedeemTx_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "GetEventStream",
			Handler:       _ArkService_GetEventStream_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "GetTransactionsStream",
			Handler:       _ArkService_GetTransactionsStream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "ark/v1/service.proto",
}
