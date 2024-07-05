package utils

import (
	"encoding/json"
	"fmt"
)

func PrintJSON(resp interface{}) error {
	jsonBytes, err := json.MarshalIndent(resp, "", "\t")
	if err != nil {
		return err
	}

	fmt.Println(string(jsonBytes))
	return nil
}
