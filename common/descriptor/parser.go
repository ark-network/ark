package descriptor

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// UnspendableKey is the x-only pubkey of the secp256k1 base point G
const UnspendableKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func ParseTaprootDescriptor(desc string) (*TaprootDescriptor, error) {
	desc = strings.ReplaceAll(desc, " ", "")

	if !strings.HasPrefix(desc, "tr(") || !strings.HasSuffix(desc, ")") {
		return nil, fmt.Errorf("invalid descriptor format")
	}

	content := desc[3 : len(desc)-1]
	parts := strings.SplitN(content, ",", 2)

	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid descriptor format: missing script tree")
	}

	internalKey, err := parseKey(parts[0])
	if err != nil {
		return nil, err
	}

	scriptTreeStr := parts[1]
	if !strings.HasPrefix(scriptTreeStr, "{") || !strings.HasSuffix(scriptTreeStr, "}") {
		return nil, fmt.Errorf("invalid script tree format")
	}
	scriptTreeStr = scriptTreeStr[1 : len(scriptTreeStr)-1]

	scriptTree := []Expression{}
	if scriptTreeStr != "" {
		scriptParts, err := splitScriptTree(scriptTreeStr)
		if err != nil {
			return nil, err
		}
		for _, scriptStr := range scriptParts {
			leaf, err := parseExpression(scriptStr)
			if err != nil {
				return nil, err
			}
			scriptTree = append(scriptTree, leaf)
		}
	}

	return &TaprootDescriptor{
		InternalKey: internalKey,
		ScriptTree:  scriptTree,
	}, nil
}

// CompileDescriptor compiles a TaprootDescriptor struct back into a descriptor string
func CompileDescriptor(desc TaprootDescriptor) string {
	scriptParts := make([]string, len(desc.ScriptTree))
	for i, leaf := range desc.ScriptTree {
		scriptParts[i] = leaf.String()
	}
	scriptTree := strings.Join(scriptParts, ",")
	return fmt.Sprintf("tr(%s,{%s})", desc.InternalKey.Hex, scriptTree)
}

func parseKey(keyStr string) (Key, error) {
	decoded, err := hex.DecodeString(keyStr)
	if err != nil {
		return Key{}, fmt.Errorf("invalid key: not a valid hex string: %v", err)
	}

	switch len(decoded) {
	case 32:
		// x-only public key, this is correct for Taproot
		return Key{Hex: keyStr}, nil
	case 33:
		// compressed public key, we need to remove the prefix byte
		return Key{Hex: keyStr[2:]}, nil
	default:
		return Key{}, fmt.Errorf("invalid key length: expected 32 or 33 bytes, got %d", len(decoded))
	}
}
func splitScriptTree(scriptTreeStr string) ([]string, error) {
	var result []string
	var current strings.Builder
	depth := 0

	for _, char := range scriptTreeStr {
		switch char {
		case '(':
			depth++
			current.WriteRune(char)
		case ')':
			depth--
			current.WriteRune(char)
			if depth == 0 {
				result = append(result, current.String())
				current.Reset()
			}
		case ',':
			if depth == 0 {
				if current.Len() > 0 {
					result = append(result, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	if depth != 0 {
		return nil, fmt.Errorf("mismatched parentheses in script tree")
	}

	return result, nil
}
