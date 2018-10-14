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

	"golang.org/x/oauth2/google"
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
	ErrECDSANotDefined = errors.New("Name of ECDSA private key is not defined")

	// ErrRSANotDefined defines error if name of RSA private key is not defined
	ErrRSANotDefined = errors.New("Name of RSA private key is not defined")

	// ErrAESNotDefined defines error if name of AES key is not defined
	ErrAESNotDefined = errors.New("Name of AES key is not defined")
)

// New creates new Cloud KMS crypto provider
func New() (*Provider, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("Failed to get default client: %+v", err)
	}
	kmsClient, err := cloudkms.New(client)
	if err != nil {
		return nil, fmt.Errorf("Failed to get Cloud KMS provider: %+v", err)
	}
	return &Provider{
		client: kmsClient,
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
// name format: projects/{id}/locations/{location}/keyRings/{name}/cryptoKeys/{name}/cryptoKeyVersions/{version}
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
		return nil, fmt.Errorf("Asymmetric sign request failed: %+v", err)

	}
	return []byte(response.Signature), nil
}

// VerifyECDSA will verify that an
// 'EC_SIGN_P384_SHA384' signature is valid for a given message
func (p Provider) VerifyECDSA(ctx context.Context, signature, plaintext []byte) error {
	key, err := p.publicECDSAKey(ctx)
	if err != nil {
		return err
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(string(signature))
	if err != nil {
		return fmt.Errorf("Failed to decode (base64): %v", err)
	}
	var parsedSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(decodedSignature, &parsedSig); err != nil {
		return fmt.Errorf("Failed to unmarshal ECDSA signature: %v", err)
	}

	hashed := sha512.Sum384(plaintext)
	if !ecdsa.Verify(key, hashed[:], parsedSig.R, parsedSig.S) {
		return fmt.Errorf("Failed to verify signed ECDSA message")
	}
	return nil
}

// EncryptRSA will encrypt a plaintext using an
// 'RSA_DECRYPT_OAEP_2048_SHA256' public key retrieved from Cloud KMS,
// message length is maximum 128 bytes
func (p Provider) EncryptRSA(ctx context.Context, plaintext []byte) ([]byte, error) {
	key, err := p.publicRSAKey(ctx)
	if err != nil {
		return nil, err
	}

	// Perform type assertion to get the RSA key.
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Unknown type of public key")
	}

	encryptedText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA encryption failed: %+v", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(encryptedText)), nil
}

// DecryptRSA will attempt to decrypt a given ciphertext with an
// 'RSA_DECRYPT_OAEP_2048_SHA256' private key stored on Cloud KMS
func (p Provider) DecryptRSA(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p.path.rsa == "" {
		return nil, ErrRSANotDefined
	}
	decryptRequest := &cloudkms.AsymmetricDecryptRequest{
		Ciphertext: string(ciphertext),
	}
	response, err := p.client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricDecrypt(p.path.rsa, decryptRequest).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("RSA decryption request failed: %+v", err)
	}
	decryptedText, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode (base64): %+v", err)

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
	resp, err := p.client.Projects.Locations.KeyRings.CryptoKeys.Encrypt(p.path.aes, req).Do()
	if err != nil {
		return nil, fmt.Errorf("AES encryption request failed: %+v", err)
	}

	return []byte(resp.Ciphertext), nil
}

// DecryptAES will attempt to decrypt a given ciphertext with an
// 'AES_P256_SHA256' key stored on Cloud KMS
func (p Provider) DecryptAES(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p.path.aes == "" {
		return nil, ErrAESNotDefined
	}
	req := &cloudkms.DecryptRequest{
		Ciphertext: string(ciphertext),
	}
	resp, err := p.client.Projects.Locations.KeyRings.CryptoKeys.Decrypt(p.path.aes, req).Do()
	if err != nil {
		return nil, fmt.Errorf("AES decryption request failed: %+v", err)
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}

// publicECDSAKey retrieves the public key from a stored ECDSA asymmetric key pair on KMS.
func (p Provider) publicECDSAKey(ctx context.Context) (*ecdsa.PublicKey, error) {
	if p.path.ecdsa == "" {
		return nil, ErrECDSANotDefined
	}
	response, err := p.client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		GetPublicKey(p.path.ecdsa).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public ECDSA key: %+v", err)
	}
	keyBytes := []byte(response.Pem)
	block, _ := pem.Decode(keyBytes)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public ECDSA key: %+v", err)
	}
	return &key.PublicKey, nil
}

// publicRSAKey retrieves the public key from a stored RSA asymmetric key pair on KMS.
func (p Provider) publicRSAKey(ctx context.Context) (interface{}, error) {
	if p.path.rsa == "" {
		return nil, ErrRSANotDefined
	}
	response, err := p.client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		GetPublicKey(p.path.rsa).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public RSA key: %+v", err)
	}
	keyBytes := []byte(response.Pem)
	block, _ := pem.Decode(keyBytes)
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public RSA key: %+v", err)
	}
	return publicKey, nil
}
