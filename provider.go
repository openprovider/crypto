package crypto

import "context"

// Provider defines interface that implemented by different providers
type Provider interface {
	// SignECDSA will sign a plaintext message using an
	// ECDSA P384 asymmetric private key
	SignECDSA(ctx context.Context, plaintext []byte) ([]byte, error)

	// VerifyECDSA will verify that an
	// ECDSA P384 signature is valid for a given plaintext message
	VerifyECDSA(ctx context.Context, signature, plaintext []byte) error

	// EncryptRSA will encrypt a plaintext message using an
	// RSA 2048 public key
	EncryptRSA(ctx context.Context, plaintext []byte) ([]byte, error)

	// DecryptRSA will attempt to decrypt a given ciphertext with an
	// RSA 2048 private key
	DecryptRSA(ctx context.Context, ciphertext []byte) ([]byte, error)

	// EncryptAES will encrypt a plaintext using an
	// AES-256 key
	EncryptAES(ctx context.Context, plaintext []byte) ([]byte, error)

	// DecryptAES will attempt to decrypt a given ciphertext with an
	// AES-256 key
	DecryptAES(ctx context.Context, ciphertext []byte) ([]byte, error)
}
