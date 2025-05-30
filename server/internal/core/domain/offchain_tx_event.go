package domain

const OffchainTxTopic = "offchain_tx"

type OffchainTxEvent struct {
	Id   string
	Type EventType
}

func (s OffchainTxEvent) GetTopic() string   { return OffchainTxTopic }
func (s OffchainTxEvent) GetType() EventType { return s.Type }

type OffchainTxRequested struct {
	OffchainTxEvent
	VirtualTx             string
	UnsignedCheckpointTxs map[string]string
	StartingTimestamp     int64
}

type OffchainTxAccepted struct {
	OffchainTxEvent
	CommitmentTxids     []string
	FinalVirtualTx      string
	SignedCheckpointTxs map[string]string
	ExpiryTimestamp     int64
}

type OffchainTxFinalized struct {
	OffchainTxEvent
	FinalCheckpointTxs map[string]string
	Timestamp          int64
}

type OffchainTxFailed struct {
	OffchainTxEvent
	Reason    string
	Timestamp int64
}
