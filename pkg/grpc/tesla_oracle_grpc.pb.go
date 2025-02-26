// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.29.3
// source: pkg/grpc/tesla_oracle.proto

package grpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	TeslaOracle_RegisterNewDevice_FullMethodName = "/tesla_oracle.TeslaOracle/RegisterNewDevice"
	TeslaOracle_GetDevicesByVIN_FullMethodName   = "/tesla_oracle.TeslaOracle/GetDevicesByVIN"
)

// TeslaOracleClient is the client API for TeslaOracle service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TeslaOracleClient interface {
	RegisterNewDevice(ctx context.Context, in *RegisterNewDeviceRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	GetDevicesByVIN(ctx context.Context, in *GetDevicesByVINRequest, opts ...grpc.CallOption) (*GetDevicesByVINResponse, error)
}

type teslaOracleClient struct {
	cc grpc.ClientConnInterface
}

func NewTeslaOracleClient(cc grpc.ClientConnInterface) TeslaOracleClient {
	return &teslaOracleClient{cc}
}

func (c *teslaOracleClient) RegisterNewDevice(ctx context.Context, in *RegisterNewDeviceRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, TeslaOracle_RegisterNewDevice_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *teslaOracleClient) GetDevicesByVIN(ctx context.Context, in *GetDevicesByVINRequest, opts ...grpc.CallOption) (*GetDevicesByVINResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetDevicesByVINResponse)
	err := c.cc.Invoke(ctx, TeslaOracle_GetDevicesByVIN_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TeslaOracleServer is the server API for TeslaOracle service.
// All implementations must embed UnimplementedTeslaOracleServer
// for forward compatibility.
type TeslaOracleServer interface {
	RegisterNewDevice(context.Context, *RegisterNewDeviceRequest) (*emptypb.Empty, error)
	GetDevicesByVIN(context.Context, *GetDevicesByVINRequest) (*GetDevicesByVINResponse, error)
	mustEmbedUnimplementedTeslaOracleServer()
}

// UnimplementedTeslaOracleServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedTeslaOracleServer struct{}

func (UnimplementedTeslaOracleServer) RegisterNewDevice(context.Context, *RegisterNewDeviceRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterNewDevice not implemented")
}
func (UnimplementedTeslaOracleServer) GetDevicesByVIN(context.Context, *GetDevicesByVINRequest) (*GetDevicesByVINResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetDevicesByVIN not implemented")
}
func (UnimplementedTeslaOracleServer) mustEmbedUnimplementedTeslaOracleServer() {}
func (UnimplementedTeslaOracleServer) testEmbeddedByValue()                     {}

// UnsafeTeslaOracleServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TeslaOracleServer will
// result in compilation errors.
type UnsafeTeslaOracleServer interface {
	mustEmbedUnimplementedTeslaOracleServer()
}

func RegisterTeslaOracleServer(s grpc.ServiceRegistrar, srv TeslaOracleServer) {
	// If the following call pancis, it indicates UnimplementedTeslaOracleServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&TeslaOracle_ServiceDesc, srv)
}

func _TeslaOracle_RegisterNewDevice_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterNewDeviceRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TeslaOracleServer).RegisterNewDevice(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TeslaOracle_RegisterNewDevice_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TeslaOracleServer).RegisterNewDevice(ctx, req.(*RegisterNewDeviceRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TeslaOracle_GetDevicesByVIN_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDevicesByVINRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TeslaOracleServer).GetDevicesByVIN(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: TeslaOracle_GetDevicesByVIN_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TeslaOracleServer).GetDevicesByVIN(ctx, req.(*GetDevicesByVINRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TeslaOracle_ServiceDesc is the grpc.ServiceDesc for TeslaOracle service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TeslaOracle_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "tesla_oracle.TeslaOracle",
	HandlerType: (*TeslaOracleServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RegisterNewDevice",
			Handler:    _TeslaOracle_RegisterNewDevice_Handler,
		},
		{
			MethodName: "GetDevicesByVIN",
			Handler:    _TeslaOracle_GetDevicesByVIN_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pkg/grpc/tesla_oracle.proto",
}
