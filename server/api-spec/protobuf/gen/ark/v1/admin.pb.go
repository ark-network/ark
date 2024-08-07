// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        (unknown)
// source: ark/v1/admin.proto

package arkv1

import (
	_ "google.golang.org/genproto/googleapis/api/annotations"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GetScheduledSweepRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetScheduledSweepRequest) Reset() {
	*x = GetScheduledSweepRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ark_v1_admin_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetScheduledSweepRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetScheduledSweepRequest) ProtoMessage() {}

func (x *GetScheduledSweepRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ark_v1_admin_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetScheduledSweepRequest.ProtoReflect.Descriptor instead.
func (*GetScheduledSweepRequest) Descriptor() ([]byte, []int) {
	return file_ark_v1_admin_proto_rawDescGZIP(), []int{0}
}

type GetScheduledSweepResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Sweeps []*ScheduledSweep `protobuf:"bytes,1,rep,name=sweeps,proto3" json:"sweeps,omitempty"`
}

func (x *GetScheduledSweepResponse) Reset() {
	*x = GetScheduledSweepResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ark_v1_admin_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetScheduledSweepResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetScheduledSweepResponse) ProtoMessage() {}

func (x *GetScheduledSweepResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ark_v1_admin_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetScheduledSweepResponse.ProtoReflect.Descriptor instead.
func (*GetScheduledSweepResponse) Descriptor() ([]byte, []int) {
	return file_ark_v1_admin_proto_rawDescGZIP(), []int{1}
}

func (x *GetScheduledSweepResponse) GetSweeps() []*ScheduledSweep {
	if x != nil {
		return x.Sweeps
	}
	return nil
}

type SweepableOutput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Txid        string `protobuf:"bytes,1,opt,name=txid,proto3" json:"txid,omitempty"`
	Vout        uint32 `protobuf:"varint,2,opt,name=vout,proto3" json:"vout,omitempty"`
	Amount      string `protobuf:"bytes,3,opt,name=amount,proto3" json:"amount,omitempty"`
	ScheduledAt int64  `protobuf:"varint,4,opt,name=scheduled_at,json=scheduledAt,proto3" json:"scheduled_at,omitempty"`
}

func (x *SweepableOutput) Reset() {
	*x = SweepableOutput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ark_v1_admin_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SweepableOutput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SweepableOutput) ProtoMessage() {}

func (x *SweepableOutput) ProtoReflect() protoreflect.Message {
	mi := &file_ark_v1_admin_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SweepableOutput.ProtoReflect.Descriptor instead.
func (*SweepableOutput) Descriptor() ([]byte, []int) {
	return file_ark_v1_admin_proto_rawDescGZIP(), []int{2}
}

func (x *SweepableOutput) GetTxid() string {
	if x != nil {
		return x.Txid
	}
	return ""
}

func (x *SweepableOutput) GetVout() uint32 {
	if x != nil {
		return x.Vout
	}
	return 0
}

func (x *SweepableOutput) GetAmount() string {
	if x != nil {
		return x.Amount
	}
	return ""
}

func (x *SweepableOutput) GetScheduledAt() int64 {
	if x != nil {
		return x.ScheduledAt
	}
	return 0
}

type ScheduledSweep struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RoundId string             `protobuf:"bytes,1,opt,name=round_id,json=roundId,proto3" json:"round_id,omitempty"`
	Outputs []*SweepableOutput `protobuf:"bytes,2,rep,name=outputs,proto3" json:"outputs,omitempty"`
}

func (x *ScheduledSweep) Reset() {
	*x = ScheduledSweep{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ark_v1_admin_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ScheduledSweep) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ScheduledSweep) ProtoMessage() {}

func (x *ScheduledSweep) ProtoReflect() protoreflect.Message {
	mi := &file_ark_v1_admin_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ScheduledSweep.ProtoReflect.Descriptor instead.
func (*ScheduledSweep) Descriptor() ([]byte, []int) {
	return file_ark_v1_admin_proto_rawDescGZIP(), []int{3}
}

func (x *ScheduledSweep) GetRoundId() string {
	if x != nil {
		return x.RoundId
	}
	return ""
}

func (x *ScheduledSweep) GetOutputs() []*SweepableOutput {
	if x != nil {
		return x.Outputs
	}
	return nil
}

type GetRoundDetailsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RoundId string `protobuf:"bytes,1,opt,name=round_id,json=roundId,proto3" json:"round_id,omitempty"`
}

func (x *GetRoundDetailsRequest) Reset() {
	*x = GetRoundDetailsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ark_v1_admin_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRoundDetailsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRoundDetailsRequest) ProtoMessage() {}

func (x *GetRoundDetailsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ark_v1_admin_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRoundDetailsRequest.ProtoReflect.Descriptor instead.
func (*GetRoundDetailsRequest) Descriptor() ([]byte, []int) {
	return file_ark_v1_admin_proto_rawDescGZIP(), []int{4}
}

func (x *GetRoundDetailsRequest) GetRoundId() string {
	if x != nil {
		return x.RoundId
	}
	return ""
}

type GetRoundDetailsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RoundId          string   `protobuf:"bytes,1,opt,name=round_id,json=roundId,proto3" json:"round_id,omitempty"`
	Txid             string   `protobuf:"bytes,2,opt,name=txid,proto3" json:"txid,omitempty"`
	ForfeitedAmount  string   `protobuf:"bytes,3,opt,name=forfeited_amount,json=forfeitedAmount,proto3" json:"forfeited_amount,omitempty"`
	TotalVtxosAmount string   `protobuf:"bytes,4,opt,name=total_vtxos_amount,json=totalVtxosAmount,proto3" json:"total_vtxos_amount,omitempty"`
	TotalExitAmount  string   `protobuf:"bytes,5,opt,name=total_exit_amount,json=totalExitAmount,proto3" json:"total_exit_amount,omitempty"`
	FeesAmount       string   `protobuf:"bytes,6,opt,name=fees_amount,json=feesAmount,proto3" json:"fees_amount,omitempty"`
	InputsVtxos      []string `protobuf:"bytes,7,rep,name=inputs_vtxos,json=inputsVtxos,proto3" json:"inputs_vtxos,omitempty"`
	OutputsVtxos     []string `protobuf:"bytes,8,rep,name=outputs_vtxos,json=outputsVtxos,proto3" json:"outputs_vtxos,omitempty"`
	ExitAddresses    []string `protobuf:"bytes,9,rep,name=exit_addresses,json=exitAddresses,proto3" json:"exit_addresses,omitempty"`
}

func (x *GetRoundDetailsResponse) Reset() {
	*x = GetRoundDetailsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ark_v1_admin_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRoundDetailsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRoundDetailsResponse) ProtoMessage() {}

func (x *GetRoundDetailsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ark_v1_admin_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRoundDetailsResponse.ProtoReflect.Descriptor instead.
func (*GetRoundDetailsResponse) Descriptor() ([]byte, []int) {
	return file_ark_v1_admin_proto_rawDescGZIP(), []int{5}
}

func (x *GetRoundDetailsResponse) GetRoundId() string {
	if x != nil {
		return x.RoundId
	}
	return ""
}

func (x *GetRoundDetailsResponse) GetTxid() string {
	if x != nil {
		return x.Txid
	}
	return ""
}

func (x *GetRoundDetailsResponse) GetForfeitedAmount() string {
	if x != nil {
		return x.ForfeitedAmount
	}
	return ""
}

func (x *GetRoundDetailsResponse) GetTotalVtxosAmount() string {
	if x != nil {
		return x.TotalVtxosAmount
	}
	return ""
}

func (x *GetRoundDetailsResponse) GetTotalExitAmount() string {
	if x != nil {
		return x.TotalExitAmount
	}
	return ""
}

func (x *GetRoundDetailsResponse) GetFeesAmount() string {
	if x != nil {
		return x.FeesAmount
	}
	return ""
}

func (x *GetRoundDetailsResponse) GetInputsVtxos() []string {
	if x != nil {
		return x.InputsVtxos
	}
	return nil
}

func (x *GetRoundDetailsResponse) GetOutputsVtxos() []string {
	if x != nil {
		return x.OutputsVtxos
	}
	return nil
}

func (x *GetRoundDetailsResponse) GetExitAddresses() []string {
	if x != nil {
		return x.ExitAddresses
	}
	return nil
}

type GetRoundsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	After  int64 `protobuf:"varint,1,opt,name=after,proto3" json:"after,omitempty"`
	Before int64 `protobuf:"varint,2,opt,name=before,proto3" json:"before,omitempty"`
}

func (x *GetRoundsRequest) Reset() {
	*x = GetRoundsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ark_v1_admin_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRoundsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRoundsRequest) ProtoMessage() {}

func (x *GetRoundsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ark_v1_admin_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRoundsRequest.ProtoReflect.Descriptor instead.
func (*GetRoundsRequest) Descriptor() ([]byte, []int) {
	return file_ark_v1_admin_proto_rawDescGZIP(), []int{6}
}

func (x *GetRoundsRequest) GetAfter() int64 {
	if x != nil {
		return x.After
	}
	return 0
}

func (x *GetRoundsRequest) GetBefore() int64 {
	if x != nil {
		return x.Before
	}
	return 0
}

type GetRoundsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Rounds []string `protobuf:"bytes,1,rep,name=rounds,proto3" json:"rounds,omitempty"`
}

func (x *GetRoundsResponse) Reset() {
	*x = GetRoundsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ark_v1_admin_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetRoundsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetRoundsResponse) ProtoMessage() {}

func (x *GetRoundsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ark_v1_admin_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetRoundsResponse.ProtoReflect.Descriptor instead.
func (*GetRoundsResponse) Descriptor() ([]byte, []int) {
	return file_ark_v1_admin_proto_rawDescGZIP(), []int{7}
}

func (x *GetRoundsResponse) GetRounds() []string {
	if x != nil {
		return x.Rounds
	}
	return nil
}

var File_ark_v1_admin_proto protoreflect.FileDescriptor

var file_ark_v1_admin_proto_rawDesc = []byte{
	0x0a, 0x12, 0x61, 0x72, 0x6b, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31, 0x1a, 0x1c, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x1a, 0x0a, 0x18, 0x47, 0x65,
	0x74, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x53, 0x77, 0x65, 0x65, 0x70, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x4b, 0x0a, 0x19, 0x47, 0x65, 0x74, 0x53, 0x63, 0x68,
	0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x53, 0x77, 0x65, 0x65, 0x70, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x2e, 0x0a, 0x06, 0x73, 0x77, 0x65, 0x65, 0x70, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x63, 0x68,
	0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x53, 0x77, 0x65, 0x65, 0x70, 0x52, 0x06, 0x73, 0x77, 0x65,
	0x65, 0x70, 0x73, 0x22, 0x74, 0x0a, 0x0f, 0x53, 0x77, 0x65, 0x65, 0x70, 0x61, 0x62, 0x6c, 0x65,
	0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x78, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x78, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x76, 0x6f,
	0x75, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x76, 0x6f, 0x75, 0x74, 0x12, 0x16,
	0x0a, 0x06, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x21, 0x0a, 0x0c, 0x73, 0x63, 0x68, 0x65, 0x64, 0x75,
	0x6c, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0b, 0x73, 0x63,
	0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x41, 0x74, 0x22, 0x5e, 0x0a, 0x0e, 0x53, 0x63, 0x68,
	0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x53, 0x77, 0x65, 0x65, 0x70, 0x12, 0x19, 0x0a, 0x08, 0x72,
	0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72,
	0x6f, 0x75, 0x6e, 0x64, 0x49, 0x64, 0x12, 0x31, 0x0a, 0x07, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74,
	0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x77, 0x65, 0x65, 0x70, 0x61, 0x62, 0x6c, 0x65, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74,
	0x52, 0x07, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x73, 0x22, 0x33, 0x0a, 0x16, 0x47, 0x65, 0x74,
	0x52, 0x6f, 0x75, 0x6e, 0x64, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x49, 0x64, 0x22, 0xdd,
	0x02, 0x0a, 0x17, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x44, 0x65, 0x74, 0x61, 0x69,
	0x6c, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f,
	0x75, 0x6e, 0x64, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x6f,
	0x75, 0x6e, 0x64, 0x49, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x78, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x78, 0x69, 0x64, 0x12, 0x29, 0x0a, 0x10, 0x66, 0x6f, 0x72,
	0x66, 0x65, 0x69, 0x74, 0x65, 0x64, 0x5f, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0f, 0x66, 0x6f, 0x72, 0x66, 0x65, 0x69, 0x74, 0x65, 0x64, 0x41, 0x6d,
	0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2c, 0x0a, 0x12, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x76, 0x74,
	0x78, 0x6f, 0x73, 0x5f, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x10, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x56, 0x74, 0x78, 0x6f, 0x73, 0x41, 0x6d, 0x6f, 0x75,
	0x6e, 0x74, 0x12, 0x2a, 0x0a, 0x11, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x65, 0x78, 0x69, 0x74,
	0x5f, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x74,
	0x6f, 0x74, 0x61, 0x6c, 0x45, 0x78, 0x69, 0x74, 0x41, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x1f,
	0x0a, 0x0b, 0x66, 0x65, 0x65, 0x73, 0x5f, 0x61, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x66, 0x65, 0x65, 0x73, 0x41, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12,
	0x21, 0x0a, 0x0c, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x73, 0x5f, 0x76, 0x74, 0x78, 0x6f, 0x73, 0x18,
	0x07, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x73, 0x56, 0x74, 0x78,
	0x6f, 0x73, 0x12, 0x23, 0x0a, 0x0d, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x73, 0x5f, 0x76, 0x74,
	0x78, 0x6f, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0c, 0x6f, 0x75, 0x74, 0x70, 0x75,
	0x74, 0x73, 0x56, 0x74, 0x78, 0x6f, 0x73, 0x12, 0x25, 0x0a, 0x0e, 0x65, 0x78, 0x69, 0x74, 0x5f,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x18, 0x09, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x0d, 0x65, 0x78, 0x69, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x65, 0x73, 0x22, 0x40,
	0x0a, 0x10, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x66, 0x74, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x03, 0x52, 0x05, 0x61, 0x66, 0x74, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x62, 0x65, 0x66, 0x6f,
	0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x06, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65,
	0x22, 0x2b, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x32, 0xd9, 0x02,
	0x0a, 0x0c, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x72,
	0x0a, 0x11, 0x47, 0x65, 0x74, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x53, 0x77,
	0x65, 0x65, 0x70, 0x12, 0x20, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74,
	0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x53, 0x77, 0x65, 0x65, 0x70, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x21, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31, 0x2e, 0x47,
	0x65, 0x74, 0x53, 0x63, 0x68, 0x65, 0x64, 0x75, 0x6c, 0x65, 0x64, 0x53, 0x77, 0x65, 0x65, 0x70,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x18, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x12,
	0x12, 0x10, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x73, 0x77, 0x65, 0x65,
	0x70, 0x73, 0x12, 0x76, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x44, 0x65,
	0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x1e, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31, 0x2e, 0x47,
	0x65, 0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31, 0x2e, 0x47,
	0x65, 0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x22, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x1c, 0x12, 0x1a,
	0x2f, 0x76, 0x31, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x2f,
	0x7b, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x5f, 0x69, 0x64, 0x7d, 0x12, 0x5d, 0x0a, 0x09, 0x47, 0x65,
	0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x12, 0x18, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31,
	0x2e, 0x47, 0x65, 0x74, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x19, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x1b, 0x82, 0xd3,
	0xe4, 0x93, 0x02, 0x15, 0x3a, 0x01, 0x2a, 0x22, 0x10, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x64, 0x6d,
	0x69, 0x6e, 0x2f, 0x72, 0x6f, 0x75, 0x6e, 0x64, 0x73, 0x42, 0x90, 0x01, 0x0a, 0x0a, 0x63, 0x6f,
	0x6d, 0x2e, 0x61, 0x72, 0x6b, 0x2e, 0x76, 0x31, 0x42, 0x0a, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x50,
	0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x3d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x61, 0x72, 0x6b, 0x2d, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x61,
	0x72, 0x6b, 0x2f, 0x61, 0x70, 0x69, 0x2d, 0x73, 0x70, 0x65, 0x63, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x61, 0x72, 0x6b, 0x2f, 0x76, 0x31, 0x3b,
	0x61, 0x72, 0x6b, 0x76, 0x31, 0xa2, 0x02, 0x03, 0x41, 0x58, 0x58, 0xaa, 0x02, 0x06, 0x41, 0x72,
	0x6b, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x06, 0x41, 0x72, 0x6b, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x12,
	0x41, 0x72, 0x6b, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0xea, 0x02, 0x07, 0x41, 0x72, 0x6b, 0x3a, 0x3a, 0x56, 0x31, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_ark_v1_admin_proto_rawDescOnce sync.Once
	file_ark_v1_admin_proto_rawDescData = file_ark_v1_admin_proto_rawDesc
)

func file_ark_v1_admin_proto_rawDescGZIP() []byte {
	file_ark_v1_admin_proto_rawDescOnce.Do(func() {
		file_ark_v1_admin_proto_rawDescData = protoimpl.X.CompressGZIP(file_ark_v1_admin_proto_rawDescData)
	})
	return file_ark_v1_admin_proto_rawDescData
}

var file_ark_v1_admin_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_ark_v1_admin_proto_goTypes = []interface{}{
	(*GetScheduledSweepRequest)(nil),  // 0: ark.v1.GetScheduledSweepRequest
	(*GetScheduledSweepResponse)(nil), // 1: ark.v1.GetScheduledSweepResponse
	(*SweepableOutput)(nil),           // 2: ark.v1.SweepableOutput
	(*ScheduledSweep)(nil),            // 3: ark.v1.ScheduledSweep
	(*GetRoundDetailsRequest)(nil),    // 4: ark.v1.GetRoundDetailsRequest
	(*GetRoundDetailsResponse)(nil),   // 5: ark.v1.GetRoundDetailsResponse
	(*GetRoundsRequest)(nil),          // 6: ark.v1.GetRoundsRequest
	(*GetRoundsResponse)(nil),         // 7: ark.v1.GetRoundsResponse
}
var file_ark_v1_admin_proto_depIdxs = []int32{
	3, // 0: ark.v1.GetScheduledSweepResponse.sweeps:type_name -> ark.v1.ScheduledSweep
	2, // 1: ark.v1.ScheduledSweep.outputs:type_name -> ark.v1.SweepableOutput
	0, // 2: ark.v1.AdminService.GetScheduledSweep:input_type -> ark.v1.GetScheduledSweepRequest
	4, // 3: ark.v1.AdminService.GetRoundDetails:input_type -> ark.v1.GetRoundDetailsRequest
	6, // 4: ark.v1.AdminService.GetRounds:input_type -> ark.v1.GetRoundsRequest
	1, // 5: ark.v1.AdminService.GetScheduledSweep:output_type -> ark.v1.GetScheduledSweepResponse
	5, // 6: ark.v1.AdminService.GetRoundDetails:output_type -> ark.v1.GetRoundDetailsResponse
	7, // 7: ark.v1.AdminService.GetRounds:output_type -> ark.v1.GetRoundsResponse
	5, // [5:8] is the sub-list for method output_type
	2, // [2:5] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_ark_v1_admin_proto_init() }
func file_ark_v1_admin_proto_init() {
	if File_ark_v1_admin_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ark_v1_admin_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetScheduledSweepRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ark_v1_admin_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetScheduledSweepResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ark_v1_admin_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SweepableOutput); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ark_v1_admin_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ScheduledSweep); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ark_v1_admin_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRoundDetailsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ark_v1_admin_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRoundDetailsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ark_v1_admin_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRoundsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ark_v1_admin_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetRoundsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ark_v1_admin_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_ark_v1_admin_proto_goTypes,
		DependencyIndexes: file_ark_v1_admin_proto_depIdxs,
		MessageInfos:      file_ark_v1_admin_proto_msgTypes,
	}.Build()
	File_ark_v1_admin_proto = out.File
	file_ark_v1_admin_proto_rawDesc = nil
	file_ark_v1_admin_proto_goTypes = nil
	file_ark_v1_admin_proto_depIdxs = nil
}
