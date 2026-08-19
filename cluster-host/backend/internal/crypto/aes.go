package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const EncryptedPrefix = "enc:"

// Encrypt encrypts a string using AES-256-GCM and returns a base64 string prefixed with "enc:"
func Encrypt(plaintext string, keyStr string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	// Ensure key is 32 bytes for AES-256
	key := padOrTruncateKey(keyStr)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return EncryptedPrefix + encoded, nil
}

// Decrypt decrypts a base64 string prefixed with "enc:". Returns unencrypted input if prefix is absent.
func Decrypt(input string, keyStr string) (string, error) {
	if input == "" {
		return "", nil
	}
	if !strings.HasPrefix(input, EncryptedPrefix) {
		// Not encrypted, return as-is (backward compatibility for unencrypted DB records)
		return input, nil
	}

	rawB64 := strings.TrimPrefix(input, EncryptedPrefix)
	ciphertext, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 ciphertext: %w", err)
	}

	key := padOrTruncateKey(keyStr)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return string(plaintext), nil
}

func padOrTruncateKey(keyStr string) []byte {
	k := []byte(keyStr)
	if len(k) >= 32 {
		return k[:32]
	}
	padded := make([]byte, 32)
	copy(padded, k)
	return padded
}
