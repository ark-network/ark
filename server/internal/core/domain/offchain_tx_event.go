package domain

const OffchainTxTopic = "offchain_tx"

func (s OffchainTxRequested) GetTopic() string { return OffchainTxTopic }
func (s OffchainTxAccepted) GetTopic() string  { return OffchainTxTopic }
func (s OffchainTxFinalized) GetTopic() string { return OffchainTxTopic }
func (s OffchainTxFailed) GetTopic() string    { return OffchainTxTopic }

type OffchainTxRequested struct {
	Id                    string
	VirtualTx             string
	UnsignedCheckpointTxs map[string]string
	Timestamp             int64
}

type OffchainTxAccepted struct {
	Id                  string
	CommitmentTxids     []string
	FinalVirtualTx      string
	SignedCheckpointTxs map[string]string
}

type OffchainTxFinalized struct {
	Id                 string
	FinalCheckpointTxs map[string]string
	Timestamp          int64
	ExpiryTimestamp    int64
}

type OffchainTxFailed struct {
	Id        string
	Reason    string
	Timestamp int64
}
