package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"runtime/debug"

	"golang.org/x/crypto/scrypt"
)

type cypher struct{}

func NewAES128Cypher() *cypher {
	return &cypher{}
}

func (c *cypher) Encrypt(privateKey, password []byte) ([]byte, error) {
	// Due to https://github.com/golang/go/issues/7168.
	// This call makes sure that memory is freed in case the GC doesn't do that
	// right after the encryption/decryption.
	defer debug.FreeOSMemory()

	if len(privateKey) == 0 {
		return nil, fmt.Errorf("missing plaintext private key")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing encryption password")
	}

	key, salt, err := deriveKey(password, nil)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, privateKey, nil)
	ciphertext = append(ciphertext, salt...)

	return ciphertext, nil
}

func (c *cypher) decrypt(encrypted, password []byte) ([]byte, error) {
	defer debug.FreeOSMemory()

	if len(encrypted) == 0 {
		return nil, fmt.Errorf("missing encrypted mnemonic")
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("missing decryption password")
	}

	salt := encrypted[len(encrypted)-32:]
	data := encrypted[:len(encrypted)-32]

	key, _, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	// #nosec G407
	nonce, text := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, text, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid password")
	}
	return plaintext, nil
}

// deriveKey derives a 32 byte array key from a custom passhprase
func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	// 2^20 = 1048576 recommended length for key-stretching
	// check the doc for other recommended values:
	// https://godoc.org/golang.org/x/crypto/scrypt
	key, err := scrypt.Key(password, salt, 1048576, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}
