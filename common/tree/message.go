package tree

import (
	"encoding/json"
)

type IntentMessage struct {
	// InputTapTrees is the list of taproot trees associated with the spent inputs
	// the index of the taproot tree in the list corresponds to the index of the input - 1
	// (we ignore the first bip322 input, as it is duplicate of the second one)
	InputTapTrees []string `json:"input_tap_trees"`
	// OnchainOutputIndexes specifies what are the outputs in the proof tx
	// that should be considered as onchain by the Ark operator
	OnchainOutputIndexes []int `json:"onchain_output_indexes"`
	// ValidAt is the timestamp (in seconds) at which the proof should be considered valid
	// if set to 0, the proof will be considered valid indefinitely or until ExpireAt is reached
	ValidAt int64 `json:"valid_at"`
	// ExpireAt is the timestamp (in seconds) at which the proof should be considered invalid
	// if set to 0, the proof will be considered valid indefinitely
	ExpireAt int64 `json:"expire_at"`
	// Musig2Data contains the related information about the vtxo tree signing
	// if the outputs are not registered in the proof or all the outputs are onchain, this field is not required
	Musig2Data *Musig2 `json:"musig2_data"`
}

func (m IntentMessage) Encode() (string, error) {
	encoded, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (m *IntentMessage) Decode(data string) error {
	return json.Unmarshal([]byte(data), m)
}
