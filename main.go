package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func generateECDSAKeyPair() error {
	// Membuat kurva elliptic P-521
	curve := elliptic.P521()

	// Membuat private key
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return err
	}

	// Mengkonversi private key ke format DER
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	// Membuat blok pem untuk private key
	privateKeyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Menyimpan private key ke file
	err = ioutil.WriteFile("private_key.pem", pem.EncodeToMemory(privateKeyBlock), 0600)
	if err != nil {
		return err
	}

	// Membuat public key
	publicKey := &privateKey.PublicKey

	// Mengkonversi public key ke format DER
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	// Membuat blok pem untuk public key
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Menyimpan public key ke file
	err = ioutil.WriteFile("public_key.pem", pem.EncodeToMemory(publicKeyBlock), 0644)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	if err := generateECDSAKeyPair(); err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	fmt.Println("Key pair generated successfully.")
}
