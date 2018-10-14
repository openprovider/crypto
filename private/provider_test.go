package private

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestSignVerifyECDSA(t *testing.T) {
	ctx := context.Background()
	data, err := generateECDSA()
	if err != nil {
		t.Error("Expected creating of new keys with ECDSA, got", err)
	}
	provider := new(Provider)
	err = provider.RegisterPrivateKeyECDSA(data)
	if err != nil {
		t.Error("Expected adding a new ECDSA key, got", err)
	}

	message := []byte("Test string 123")
	signature, err := provider.SignECDSA(ctx, message)
	if err != nil {
		t.Error("Expected successful sign operation, got", err)
	}
	if signature == nil {
		t.Error("Expected signature, got empty data")
	}
	err = provider.VerifyECDSA(ctx, signature, append(message, []byte("++++++++++++")...))
	if err == nil {
		t.Error("Expected error of verifying message, got nil")
	}
	err = provider.VerifyECDSA(ctx, signature, message)
	if err != nil {
		t.Error("Expected successful verifying operation, got", err)
	}
}

func BenchmarkSignVerifyECDSA(b *testing.B) {
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		b.Error("Expected creating of new ECDSA private key, got", err)
	}
	provider := New(key, nil, nil)
	message := []byte("Test encrypt message")
	for i := 0; i < b.N; i++ {
		signature, err := provider.SignECDSA(ctx, message)
		if err != nil {
			b.Error("Expected successful sign operation, got", err)
		}
		err = provider.VerifyECDSA(ctx, signature, message)
		if err != nil {
			b.Error("Expected successful verifying operation, got", err)
		}
	}
}

func TestEncryptDecryptRSA(t *testing.T) {
	ctx := context.Background()
	data, err := generateRSA()
	if err != nil {
		t.Error("Expected creating of new keys with RSA, got", err)
	}
	provider := new(Provider)
	err = provider.RegisterPrivateKeyRSA(data)
	if err != nil {
		t.Error("Expected adding a new RSA key, got", err)
	}

	message := []byte("Test string 123")
	_, err = provider.EncryptRSA(ctx, bytes.Repeat(message, 50))
	if err == nil {
		t.Error("Expected error of encrypt too long message, got nil")
	}
	encryptedMessage, err := provider.EncryptRSA(ctx, message)
	if err != nil {
		t.Error("Expected successful encrypt operation, got", err)
	}
	if encryptedMessage == nil {
		t.Error("Expected encrypted message, got empty string")
	}
	_, err = provider.DecryptRSA(ctx, append(encryptedMessage, []byte("++++++++++++")...))
	if err == nil {
		t.Error("Expected error of decoding base64, got nil")
	}
	decryptedMessage, err := provider.DecryptRSA(ctx, encryptedMessage)
	if err != nil {
		t.Error("Expected successful decrypt operation, got", err)
	}
	if !reflect.DeepEqual(message, decryptedMessage) {
		t.Errorf("Expected message '%s', got '%s'", message, decryptedMessage)
	}
	_, err = provider.DecryptRSA(ctx, []byte(base64.StdEncoding.EncodeToString([]byte("Not encrypted message"))))
	if err == nil {
		t.Error("Expected error of decrypt message, got nil")
	}
}

func BenchmarkEncryptDecryptRSA(b *testing.B) {
	ctx := context.Background()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Error("Expected creating of new RSA private key, got", err)
	}
	provider := New(nil, key, nil)
	message := []byte("Test encrypt message")
	for i := 0; i < b.N; i++ {
		encryptedMessage, err := provider.EncryptRSA(ctx, message)
		if err != nil {
			b.Error("Expected successful encrypt operation, got", err)
		}
		_, err = provider.DecryptRSA(ctx, encryptedMessage)
		if err != nil {
			b.Error("Expected successful decrypt operation, got", err)
		}
	}
}

func TestEncryptDecryptAES(t *testing.T) {
	ctx := context.Background()
	data, err := generateAES()
	if err != nil {
		t.Error("Expected creating of new keys with ECDSA, got", err)
	}
	provider := new(Provider)
	err = provider.RegisterKeyAES(data)
	if err != nil {
		t.Error("Expected adding a new AES key, got", err)
	}

	message := []byte("Test string 123")
	encryptedMessage, err := provider.EncryptAES(ctx, message)
	if err != nil {
		t.Error("Expected successful encrypt operation, got", err)
	}
	if encryptedMessage == nil {
		t.Error("Expected encrypted message, got empty string")
	}
	_, err = provider.DecryptAES(ctx, append(encryptedMessage, []byte("++++++++++++")...))
	if err == nil {
		t.Error("Expected error of decoding base64, got nil")
	}
	decryptedMessage, err := provider.DecryptAES(ctx, encryptedMessage)
	if err != nil {
		t.Error("Expected successful decrypt operation, got", err)
	}
	if !reflect.DeepEqual(message, decryptedMessage) {
		t.Errorf("Expected message '%s', got '%s'", message, decryptedMessage)
	}
	_, err = provider.DecryptAES(ctx, []byte(base64.StdEncoding.EncodeToString([]byte("Not encrypted message"))))
	if err == nil {
		t.Error("Expected error of decrypt message, got nil")
	}
}

func BenchmarkEncryptDecryptAES(b *testing.B) {
	ctx := context.Background()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		b.Error("Expected creating a new AES key, got", err)
	}
	provider := New(nil, nil, key)
	message := []byte("Test encrypt message")
	for i := 0; i < b.N; i++ {
		encryptedMessage, err := provider.EncryptAES(ctx, message)
		if err != nil {
			b.Error("Expected successful encrypt operation, got", err)
		}
		_, err = provider.DecryptAES(ctx, encryptedMessage)
		if err != nil {
			b.Error("Expected successful decrypt operation, got", err)
		}
	}
}

func TestKeysNotDefined(t *testing.T) {
	ctx := context.Background()
	provider := New(nil, nil, nil)
	_, err := provider.SignECDSA(ctx, []byte(""))
	if err == nil || err != ErrECDSANotDefined {
		t.Errorf("Expected error '%v', got nil", ErrECDSANotDefined)
	}
	if err != ErrECDSANotDefined {
		t.Errorf("Expected error '%v', got %v", ErrECDSANotDefined, err)
	}
	err = provider.VerifyECDSA(ctx, []byte(""), []byte(""))
	if err == nil {
		t.Errorf("Expected error '%v', got nil", ErrECDSANotDefined)
	}
	if err != ErrECDSANotDefined {
		t.Errorf("Expected error '%v', got %v", ErrECDSANotDefined, err)
	}
	_, err = provider.EncryptRSA(ctx, []byte(""))
	if err == nil {
		t.Errorf("Expected error '%v', got nil", ErrRSANotDefined)
	}
	if err != ErrRSANotDefined {
		t.Errorf("Expected error '%v', got %v", ErrRSANotDefined, err)
	}
	_, err = provider.DecryptRSA(ctx, []byte(""))
	if err == nil {
		t.Errorf("Expected error '%v', got nil", ErrRSANotDefined)
	}
	if err != ErrRSANotDefined {
		t.Errorf("Expected error '%v', got %v", ErrRSANotDefined, err)
	}
	_, err = provider.EncryptAES(ctx, []byte(""))
	if err == nil {
		t.Errorf("Expected error '%v', got nil", ErrAESNotDefined)
	}
	if err != ErrAESNotDefined {
		t.Errorf("Expected error '%v', got %v", ErrAESNotDefined, err)
	}
	_, err = provider.DecryptAES(ctx, []byte(""))
	if err == nil {
		t.Errorf("Expected error '%v', got nil", ErrAESNotDefined)
	}
	if err != ErrAESNotDefined {
		t.Errorf("Expected error '%v', got %v", ErrAESNotDefined, err)
	}
}

func generateECDSA() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  TypeECDSA,
		Bytes: block,
	}), nil
}

func generateRSA() ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	block, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  TypeRSA,
		Bytes: block,
	}), nil
}

func generateAES() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  TypeAES,
		Bytes: key,
	}), nil
}
