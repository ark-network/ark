package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"syscall"

	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

func ReadPassword(ctx *cli.Context, verify bool) ([]byte, error) {
	password := []byte(ctx.String("password"))

	if len(password) == 0 {
		fmt.Print("unlock your wallet with password: ")
		var err error
		password, err = term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // new line
		if err != nil {
			return nil, err
		}

	}

	if verify {
		if err := verifyPassword(ctx, password); err != nil {
			return nil, err
		}
	}

	return password, nil
}

func HashPassword(password []byte) []byte {
	hash := sha256.Sum256(password)
	return hash[:]
}

func verifyPassword(ctx *cli.Context, password []byte) error {
	state, err := GetState(ctx)
	if err != nil {
		return err
	}

	passwordHashString := state[PASSWORD_HASH]
	if len(passwordHashString) <= 0 {
		return fmt.Errorf("missing password hash")
	}

	passwordHash, err := hex.DecodeString(passwordHashString)
	if err != nil {
		return err
	}

	currentPassHash := HashPassword(password)

	if !bytes.Equal(passwordHash, currentPassHash) {
		return fmt.Errorf("invalid password")
	}

	return nil
}
