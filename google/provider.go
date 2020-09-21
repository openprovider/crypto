package google

import (
	"context"
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
	"math/big"

	"google.golang.org/api/cloudkms/v1"
)

// Provider implements GKM crypto provider
type Provider struct {
	client *cloudkms.Service
	path   struct {
		ecdsa string
		rsa   string
		aes   string
	}
}

var (
	// ErrECDSANotDefined defines error if name of ECDSA private key is not defined
	ErrECDSANotDefined = errors.New("name of ECDSA private key is not defined")
	// ErrECDSAVerifyFalse defines error if signature is not valid for given message
	ErrECDSAVerifyFalse = errors.New("signature is not valid for given message")
	// ErrECDSAUnknown defines error for unknown type of ECDSA public key
	ErrECDSAUnknown = errors.New("unknown type of ECDSA public key")

	// ErrKeyNotDefined defines error if name of private key is not defined
	ErrKeyNotDefined = errors.New("name of private key is not defined")

	// ErrRSANotDefined defines error if name of RSA private key is not defined
	ErrRSANotDefined = errors.New("name of RSA private key is not defined")
	// ErrRSAUnknown defines error for unknown type of RSA public key
	ErrRSAUnknown = errors.New("unknown type of RSA public key")

	// ErrAESNotDefined defines error if name of AES key is not defined
	ErrAESNotDefined = errors.New("name of AES key is not defined")
)

// New creates new Cloud KMS crypto provider
func New() (*Provider, error) {
	client, err := cloudkms.NewService(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get Cloud KMS provider: %+v", err)
	}

	return &Provider{
		client: client,
	}, nil
}

// RegisterECDSA accepts specified name/ID of ECDSA asymmetric key in Cloud KMS
// name format: projects/{id}/locations/{location}/keyRings/{name}/cryptoKeys/{name}/cryptoKeyVersions/{version}
func (p *Provider) RegisterECDSA(name string) {
	p.path.ecdsa = name
}

// RegisterRSA accepts specified name/ID of RSA asymmetric key in Cloud KMS
// name format: projects/{id}/locations/{location}/keyRings/{name}/cryptoKeys/{name}/cryptoKeyVersions/{version}
func (p *Provider) RegisterRSA(name string) {
	p.path.rsa = name
}

// RegisterAES accepts specified name/ID of AES symmetric key in Cloud KMS
// name format: projects/{id}/locations/{location}/keyRings/{name}/cryptoKeys/{name}
func (p *Provider) RegisterAES(name string) {
	p.path.aes = name
}

// SignECDSA will sign a plaintext message using an
// 'EC_SIGN_P384_SHA384' asymmetric private key retrieved from Cloud KMS
func (p Provider) SignECDSA(ctx context.Context, plaintext []byte) ([]byte, error) {
	if p.path.ecdsa == "" {
		return nil, ErrECDSANotDefined
	}

	hashed := sha512.Sum384(plaintext)
	asymmetricSignRequest := &cloudkms.AsymmetricSignRequest{
		Digest: &cloudkms.Digest{
			Sha384: base64.StdEncoding.EncodeToString(hashed[:]),
		},
	}

	response, err := p.client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricSign(p.path.ecdsa, asymmetricSignRequest).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("asymmetric sign request failed: %+v", err)
	}

	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil {
		return nil, fmt.Errorf("asymmetric sign failed to decode (base64): %+v", err)
	}

	return signature, nil
}

// VerifyECDSA will verify that an
// 'EC_SIGN_P384_SHA384' signature is valid for a given message
func (p Provider) VerifyECDSA(ctx context.Context, signature, plaintext []byte) error {
	key, err := p.publicKey(ctx, p.path.ecdsa)
	if err != nil {
		return err
	}

	// Perform type assertion to get the RSA key.
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return ErrECDSAUnknown
	}

	var parsedSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signature, &parsedSig); err != nil {
		return fmt.Errorf("failed to unmarshal ECDSA signature: %v", err)
	}

	hashed := sha512.Sum384(plaintext)
	if !ecdsa.Verify(ecdsaKey, hashed[:], parsedSig.R, parsedSig.S) {
		return ErrECDSAVerifyFalse
	}

	return nil
}

// EncryptRSA will encrypt a plaintext using an
// 'RSA_DECRYPT_OAEP_2048_SHA256' public key retrieved from Cloud KMS,
// message length is maximum 128 bytes
func (p Provider) EncryptRSA(ctx context.Context, plaintext []byte) ([]byte, error) {
	key, err := p.publicKey(ctx, p.path.rsa)
	if err != nil {
		return nil, err
	}

	// Perform type assertion to get the RSA key.
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, ErrRSAUnknown
	}

	encryptedText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA encryption failed: %+v", err)
	}

	return encryptedText, nil
}

// DecryptRSA will attempt to decrypt a given ciphertext with an
// 'RSA_DECRYPT_OAEP_2048_SHA256' private key stored on Cloud KMS
func (p Provider) DecryptRSA(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p.path.rsa == "" {
		return nil, ErrRSANotDefined
	}

	decryptRequest := &cloudkms.AsymmetricDecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	response, err := p.client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricDecrypt(p.path.rsa, decryptRequest).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("RSA decryption request failed: %+v", err)
	}

	decryptedText, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("RSA failed to decode (base64): %+v", err)
	}

	return decryptedText, nil
}

// EncryptAES will encrypt a plaintext using an
// 'AES_P256_SHA256' key retrieved from Cloud KMS,
func (p Provider) EncryptAES(ctx context.Context, plaintext []byte) ([]byte, error) {
	if p.path.aes == "" {
		return nil, ErrAESNotDefined
	}

	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}

	response, err := p.client.Projects.Locations.KeyRings.CryptoKeys.Encrypt(p.path.aes, req).Do()
	if err != nil {
		return nil, fmt.Errorf("AES encryption request failed: %+v", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(response.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("AES failed to decode (base64): %+v", err)
	}

	return ciphertext, nil
}

// DecryptAES will attempt to decrypt a given ciphertext with an
// 'AES_P256_SHA256' key stored on Cloud KMS
func (p Provider) DecryptAES(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p.path.aes == "" {
		return nil, ErrAESNotDefined
	}

	req := &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	response, err := p.client.Projects.Locations.KeyRings.CryptoKeys.Decrypt(p.path.aes, req).Do()
	if err != nil {
		return nil, fmt.Errorf("AES decryption request failed: %+v", err)
	}

	return base64.StdEncoding.DecodeString(response.Plaintext)
}

// publicKey retrieves the public key from a stored asymmetric key pair on KMS.
func (p Provider) publicKey(ctx context.Context, key string) (interface{}, error) {
	if key == "" {
		return nil, ErrKeyNotDefined
	}

	response, err := p.client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		GetPublicKey(key).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %+v", err)
	}

	keyBytes := []byte(response.Pem)
	block, _ := pem.Decode(keyBytes)

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %+v", err)
	}

	return publicKey, nil
}
