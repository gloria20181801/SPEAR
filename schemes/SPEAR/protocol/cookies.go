package spear

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
)

var (
	ErrInvalidPrivateKey  = errors.New("invalid Ed25519 private key length")
	ErrInvalidPublicKey   = errors.New("invalid Ed25519 public key length")
	ErrVerifyFailed       = errors.New("signature verification failed")
	ErrInvalidAESKeySize  = errors.New("AES key must be 16, 24, or 32 bytes")
	ErrCipherTextTooShort = errors.New("ciphertext is too short")
)

func Sign(privateKey ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrInvalidPrivateKey
	}
	return ed25519.Sign(privateKey, message), nil
}

func Verify(publicKey ed25519.PublicKey, message []byte, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidPublicKey
	}
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrVerifyFailed
	}
	return nil
}

func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrInvalidAESKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrInvalidAESKeySize
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, ErrCipherTextTooShort
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrCipherTextTooShort
	}

	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, sealed, nil)
}
