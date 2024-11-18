package descriptor

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ark-network/ark/common"
	"github.com/btcsuite/btcd/txscript"
)

var (
	ErrInvalidXOnlyKey    = errors.New("invalid x only public key")
	ErrInvalidPkPolicy    = errors.New("invalid public key policy")
	ErrInvalidOlderPolicy = errors.New("invalid older policy")
	ErrInvalidAndPolicy   = errors.New("invalid and() policy")
	ErrNotExpectedPolicy  = errors.New("not the expected policy")
)

const (
	andTokenSize = len("and(")
)

type Expression interface {
	Parse(policy string) error
	Script(verify bool) (string, error)
	String() string
}

type XOnlyKey struct {
	Key
}

func (e *XOnlyKey) Parse(policy string) error {
	if len(policy) != 64 {
		fmt.Println(policy)
		return ErrInvalidXOnlyKey
	}

	e.Hex = policy
	return nil
}

func (e *XOnlyKey) Script() string {
	return e.Hex
}

// pk(xonlypubkey)
type PK struct {
	Key XOnlyKey
}

func (e *PK) String() string {
	return fmt.Sprintf("pk(%s)", e.Key.Hex)
}

func (e *PK) Parse(policy string) error {
	if !strings.HasPrefix(policy, "pk(") {
		return ErrNotExpectedPolicy
	}
	if len(policy) != 3+64+1 {
		return ErrInvalidPkPolicy
	}

	var key XOnlyKey
	if err := key.Parse(policy[3 : 64+3]); err != nil {
		return err
	}

	e.Key = key
	return nil
}

func (e *PK) Script(verify bool) (string, error) {
	pubkeyBytes, err := hex.DecodeString(e.Key.Hex)
	if err != nil {
		return "", err
	}

	checksig := txscript.OP_CHECKSIG
	if verify {
		checksig = txscript.OP_CHECKSIGVERIFY
	}

	script, err := txscript.NewScriptBuilder().AddData(
		pubkeyBytes,
	).AddOp(
		byte(checksig),
	).Script()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(script), nil
}

type Older struct {
	Timeout uint
}

func (e *Older) String() string {
	return fmt.Sprintf("older(%d)", e.Timeout)
}

func (e *Older) Parse(policy string) error {
	if !strings.HasPrefix(policy, "older(") {
		return ErrNotExpectedPolicy
	}

	index := strings.IndexRune(policy, ')')
	if index == -1 {
		return ErrInvalidOlderPolicy
	}

	number := policy[6:index]
	if len(number) == 0 {
		return ErrInvalidOlderPolicy
	}

	timeout, err := strconv.Atoi(number)
	if err != nil {
		return ErrInvalidOlderPolicy
	}

	e.Timeout = uint(timeout)

	return nil
}

func (e *Older) Script(bool) (string, error) {
	sequence, err := common.BIP68Sequence(e.Timeout)
	if err != nil {
		return "", err
	}

	script, err := txscript.NewScriptBuilder().
		AddInt64(int64(sequence)).
		AddOps([]byte{
			txscript.OP_CHECKSEQUENCEVERIFY,
			txscript.OP_DROP,
		}).
		Script()
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(script), nil
}

type And struct {
	First  Expression
	Second Expression
}

func (e *And) String() string {
	return fmt.Sprintf("and(%s,%s)", e.First.String(), e.Second.String())
}

func (e *And) Parse(policy string) error {
	if !strings.HasPrefix(policy, "and(") {
		return ErrNotExpectedPolicy
	}

	parts, err := splitScriptTree(policy[andTokenSize : len(policy)-1])
	if err != nil {
		return ErrInvalidAndPolicy
	}

	if len(parts) != 2 {
		return ErrInvalidAndPolicy
	}

	first, err := parseExpression(parts[0])
	if err != nil {
		return err
	}

	second, err := parseExpression(parts[1])
	if err != nil {
		return err
	}

	e.First = first
	e.Second = second

	return nil
}

func (e *And) Script(verify bool) (string, error) {
	firstScript, err := e.First.Script(true)
	if err != nil {
		return "", err
	}

	secondScript, err := e.Second.Script(verify)
	if err != nil {
		return "", err
	}

	return firstScript + secondScript, nil
}

func parseExpression(policy string) (Expression, error) {
	policy = strings.TrimSpace(policy)
	if policy[0] == '{' {
		policy = policy[1:]
	}
	expressions := make([]Expression, 0)
	expressions = append(expressions, &PK{})
	expressions = append(expressions, &Older{})
	expressions = append(expressions, &And{})

	for _, e := range expressions {
		if err := e.Parse(policy); err != nil {
			if err != ErrNotExpectedPolicy {
				return nil, err
			}
			continue
		}

		return e, nil
	}

	return nil, fmt.Errorf("unable to parse expression '%s'", policy)
}
