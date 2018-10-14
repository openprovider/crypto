package private

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Provider implements private crypto provider
type Provider struct {
	ecdsa *ecdsa.PrivateKey
	rsa   *rsa.PrivateKey
	aes   []byte
}

var (
	// ErrECDSADecodePEM defines error of PEM decoding for ECDSA key
	ErrECDSADecodePEM = errors.New("Failed to decode PEM block containing ECDSA private key")
	// ErrECDSAVerifyFalse defines error if signature is not valid for given message
	ErrECDSAVerifyFalse = errors.New("Signature is not valid for given message")
	// ErrECDSANotDefined defines error if ECDSA private key is not defined
	ErrECDSANotDefined = errors.New("ECDSA private key is not defined")

	// ErrRSADecodePEM defines error of PEM decoding for RSA key
	ErrRSADecodePEM = errors.New("Failed to decode PEM block containing RSA private key")
	// ErrRSAUnknown defines error for unknown type of RSA key
	ErrRSAUnknown = errors.New("Unknown type of RSA private key")
	// ErrRSANotDefined defines error if RSA private key is not defined
	ErrRSANotDefined = errors.New("RSA private key is not defined")

	// ErrAESDecodePEM defines error of PEM decoding for AES key
	ErrAESDecodePEM = errors.New("Failed to decode PEM block containing AES key")
	// ErrAESNotDefined defines error if AES key is not defined
	ErrAESNotDefined = errors.New("AES key is not defined")
)

// PEM Block types
const (
	TypeECDSA = "EC PRIVATE KEY"
	TypeRSA   = "PRIVATE KEY"
	TypeAES   = "AES KEY"
)

// New creates a new crypto provider initialized by ECDSA, RSA private keys and AES key
func New(ecdsaKey *ecdsa.PrivateKey, rsaKey *rsa.PrivateKey, aesKey []byte) *Provider {
	return &Provider{
		ecdsa: ecdsaKey,
		rsa:   rsaKey,
		aes:   aesKey,
	}
}

// RegisterPrivateKeyECDSA decodes and register ECDSA private key from specified PEM block
func (p *Provider) RegisterPrivateKeyECDSA(data []byte) error {
	if data == nil {
		return ErrECDSANotDefined
	}
	blockECDSA, rest := pem.Decode(data)
	if blockECDSA == nil || blockECDSA.Type != TypeECDSA || len(rest) != 0 {
		return ErrECDSADecodePEM
	}
	var err error
	p.ecdsa, err = x509.ParseECPrivateKey(blockECDSA.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to parse ECDCA private key: %v", err)
	}

	return nil
}

// RegisterPrivateKeyRSA decodes and register RSA private key from specified PEM block
func (p *Provider) RegisterPrivateKeyRSA(data []byte) error {
	if data == nil {
		return ErrRSANotDefined
	}
	blockRSA, rest := pem.Decode(data)
	if blockRSA == nil || blockRSA.Type != TypeRSA || len(rest) != 0 {
		return ErrRSADecodePEM
	}
	rsaKey, err := x509.ParsePKCS8PrivateKey(blockRSA.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to parse DER encoded RSA private key: %v", err)
	}

	var ok bool
	p.rsa, ok = rsaKey.(*rsa.PrivateKey)
	if !ok {
		return ErrRSAUnknown
	}

	return nil
}

// RegisterKeyAES decodes and adds AES key from specified PEM block
func (p *Provider) RegisterKeyAES(data []byte) error {
	if data == nil {
		return ErrAESNotDefined
	}
	blockAES, rest := pem.Decode(data)
	if blockAES == nil || blockAES.Type != TypeAES || len(rest) != 0 {
		return ErrAESDecodePEM
	}
	p.aes = blockAES.Bytes

	return nil
}

// internal structure that represent ECDSA signature
type ecdsaSignature struct {
	R, S *big.Int
}

// SignECDSA will sign a plaintext message using an
// ECDSA P384 asymmetric private key
func (p Provider) SignECDSA(ctx context.Context, plaintext []byte) ([]byte, error) {
	if p.ecdsa == nil {
		return nil, ErrECDSANotDefined
	}

	hashed := sha512.Sum384(plaintext)
	r, s, err := ecdsa.Sign(rand.Reader, p.ecdsa, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("Failed to sign using ECDSA: %v", err)
	}
	signature, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal ECDSA signature: %v", err)
	}

	return []byte(base64.StdEncoding.EncodeToString(signature)), nil
}

// VerifyECDSA will verify that an
// ECDSA P384 signature is valid for a given plaintext message
func (p Provider) VerifyECDSA(ctx context.Context, signature, plaintext []byte) error {
	var es ecdsaSignature

	if p.ecdsa == nil {
		return ErrECDSANotDefined
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return fmt.Errorf("Failed to decode (base64): %v", err)
	}
	if _, err := asn1.Unmarshal(decodedSignature, &es); err != nil {
		return fmt.Errorf("Failed to unmarshal ECDSA signature: %v", err)
	}

	hashed := sha512.Sum384(plaintext)
	if !ecdsa.Verify(&p.ecdsa.PublicKey, hashed[:], es.R, es.S) {
		return ErrECDSAVerifyFalse
	}
	return nil
}

// EncryptRSA will encrypt a plaintext message using an
// RSA 2048 public key
// plaintext message length is maximum 240 bytes
// (2048 bits minus padding: 11 bytes for PKCS#1 v1.5 padding)
func (p Provider) EncryptRSA(ctx context.Context, plaintext []byte) ([]byte, error) {
	if p.rsa == nil {
		return nil, ErrRSANotDefined
	}

	encryptedText, err := rsa.EncryptOAEP(
		sha256.New(), rand.Reader,
		&p.rsa.PublicKey, plaintext, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("Failed to encrypt message: %v", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(encryptedText)), nil
}

// DecryptRSA will attempt to decrypt a given ciphertext with an
// RSA 2048 private key
func (p Provider) DecryptRSA(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p.rsa == nil {
		return nil, ErrRSANotDefined
	}

	encryptedText, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("Failed to decode (base64): %v", err)
	}
	decryptedText, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, p.rsa, encryptedText, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode decryted string: %v", err)
	}
	return decryptedText, nil
}

// EncryptAES will encrypt a plaintext using an
// AES-256 key
func (p Provider) EncryptAES(ctx context.Context, plaintext []byte) ([]byte, error) {
	if p.aes == nil {
		return nil, ErrAESNotDefined
	}

	c, err := aes.NewCipher(p.aes)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new GCM block: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("Failed to read random sequence: %v", err)
	}

	return []byte(base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plaintext, nil))), nil
}

// DecryptAES will attempt to decrypt a given ciphertext with an
// AES-256 key
func (p Provider) DecryptAES(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p.aes == nil {
		return nil, ErrAESNotDefined
	}

	encryptedText, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("Failed to decode (base64): %v", err)
	}
	c, err := aes.NewCipher(p.aes)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new cipher block: %v", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("Failed to create new GCM block: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedText) < nonceSize {
		return nil, fmt.Errorf("%s", "Ciphertext too short")
	}

	nonce, encryptedText := encryptedText[:nonceSize], encryptedText[nonceSize:]
	return gcm.Open(nil, nonce, encryptedText, nil)
}