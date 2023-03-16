package tests

import (
	"testing"

	"github.com/crossle/libsignal-protocol-go/ecc"
	"github.com/crossle/libsignal-protocol-go/logger"
	"github.com/crossle/libsignal-protocol-go/util/keyhelper"
)

// TestIdentityKeys checks generating, signing, and verifying of identity keys.
func TestIdentityKeys(t *testing.T) {
	logger.Info("Testing identity key generation...")

	// Generate an identity keypair
	identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Error("Error generating identity keys")
	}
	privateKey := identityKeyPair.PrivateKey()
	publicKey := identityKeyPair.PublicKey()
	logger.Info("  Identity KeyPair:", identityKeyPair)

	// Sign the text "Hello" with the identity key
	message := []byte("Hello")
	unsignedMessage := []byte("SHIT!")
	logger.Info("Signing bytes:", message)
	signature := ecc.CalculateSignature(privateKey, message)
	logger.Info("  Signature:", signature)

	// Validate the signature using the private key
	//valid := ecc.Verify(publicKey.PublicKey().PublicKey(), message, &signature)
	logger.Info("Verifying signature against bytes:", message)
	valid := ecc.VerifySignature(publicKey.PublicKey(), message, signature)
	logger.Info("  Valid signature:", valid)
	if !(valid) {
		t.Error("Signature verification failed.")
	}

	// Try checking the signature on text that is different
	logger.Info("Verifying signature against unsigned bytes:", unsignedMessage)
	valid = ecc.VerifySignature(publicKey.PublicKey(), unsignedMessage, signature)
	logger.Info("  Valid signature:", valid)
	if valid {
		t.Error("Signature verification should have failed here.")
	}

}
