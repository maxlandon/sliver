package cryptography

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"

	// {{if .Config.Debug}}
	"log"
	// {{end}}
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

var (
	totpOptions = totp.ValidateOpts{
		Digits:    8,
		Algorithm: otp.AlgorithmSHA256,
		Period:    uint(30),
		Skew:      uint(1),
	}

	// ErrReplayAttack - Replay attack
	ErrReplayAttack = errors.New("replay attack detected")
	// ErrDecryptFailed
	ErrDecryptFailed = errors.New("decryption failed")
)

// ECCKeyPair - Holds the public/private key pair
type ECCKeyPair struct {
	Public  *[32]byte
	Private *[32]byte
}

// ECCEncrypt - Encrypt using Nacl Box
func ECCEncrypt(recipientPublicKey *[32]byte, senderPrivateKey *[32]byte, plaintext []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	encrypted := box.Seal(nonce[:], plaintext, &nonce, recipientPublicKey, senderPrivateKey)
	return encrypted, nil
}

// ECCDecrypt - Decrypt using Curve 25519 + ChaCha20Poly1305
func ECCDecrypt(senderPublicKey *[32]byte, recipientPrivateKey *[32]byte, ciphertext []byte) ([]byte, error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])
	plaintext, ok := box.Open(nil, ciphertext[24:], &decryptNonce, senderPublicKey, recipientPrivateKey)
	if !ok {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

// RandomKey - Generate random ID of randomIDSize bytes
func RandomKey() [chacha20poly1305.KeySize]byte {
	randBuf := make([]byte, 64)
	rand.Read(randBuf)
	return deriveKeyFrom(randBuf)
}

// deriveKeyFrom - Derives a key from input data using SHA256
func deriveKeyFrom(data []byte) [chacha20poly1305.KeySize]byte {
	digest := sha256.Sum256(data)
	var key [chacha20poly1305.KeySize]byte
	copy(key[:], digest[:chacha20poly1305.KeySize])
	return key
}

// Encrypt - Encrypt using chacha20poly1305
// https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
func Encrypt(key [chacha20poly1305.KeySize]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt - Decrypt using chacha20poly1305
// https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
func Decrypt(key [chacha20poly1305.KeySize]byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	// Decrypt the message and check it wasn't tampered with.
	return aead.Open(nil, nonce, ciphertext, nil)
}

// NewCipherContext - Wrapper around creating a cipher context from a key
func NewCipherContext(key [chacha20poly1305.KeySize]byte) *CipherContext {
	return &CipherContext{
		Key:    key,
		replay: &sync.Map{},
	}
}

// CipherContext - Tracks a series of messages encrypted under the same key
// and detects/prevents replay attacks.
type CipherContext struct {
	Key    [chacha20poly1305.KeySize]byte
	replay *sync.Map
}

// Decrypt - Decrypt a message with the contextual key and check for replay attacks
func (c *CipherContext) Decrypt(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	hexDigest := hex.EncodeToString(digest[:])
	if _, ok := c.replay.LoadOrStore(hexDigest, true); ok {
		return nil, ErrReplayAttack
	}
	plaintext, err := Decrypt(c.Key, data)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Encrypt - Encrypt a message with the contextual key
func (c *CipherContext) Encrypt(plaintext []byte) ([]byte, error) {
	ciphertext, err := Encrypt(c.Key, plaintext)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(ciphertext)
	hexDigest := hex.EncodeToString(digest[:])
	c.replay.Store(hexDigest, true)
	return ciphertext, nil
}

// GetOTPCode - Get the current OTP code
func GetOTPCode() string {
	now := time.Now().UTC()
	code, _ := totp.GenerateCodeCustom(TOTPSecret, now, totpOptions)
	// {{if .Config.Debug}}
	log.Printf("TOTP Code: %s", code)
	// {{end}}
	return code
}

// ValidateTOTP - Validate a TOTP code
func ValidateTOTP(code string) (bool, error) {
	now := time.Now().UTC()
	valid, err := totp.ValidateCustom(code, TOTPSecret, now, totpOptions)
	if err != nil {
		return false, err
	}
	return valid, nil
}
