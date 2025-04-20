package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	keyFile := flag.String("key", "", "Path to private key file")
	certFile := flag.String("cert", "", "Path to certificate file")
	caFiles := flag.String("cachain", "", "Comma-separated paths to CA chain files (subca.pem,rootca.pem) or to a single file")
	
	flag.Parse()

	if *certFile == "" {
		fmt.Println("Error: -cert parameter is required")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Option 1: all parameters provided
	if *keyFile != "" && *certFile != "" && *caFiles != "" {
		fmt.Println("Running full verification (key, cert match, and chain validation)")
		
		// 1. Validate key
		if err := validateKey(*keyFile); err != nil {
			fmt.Printf("❌ Key validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key is valid")

		// 2. Verify key and certificate match
		if err := verifyKeyCertMatch(*keyFile, *certFile); err != nil {
			fmt.Printf("❌ Key and certificate mismatch: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key matches certificate")

		// 3. Verify certificate chain
		if err := verifyCertChain(*certFile, *caFiles); err != nil {
			fmt.Printf("❌ Certificate chain validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Certificate chain is valid")
		
		return
	}

	// Option 2: only key and cert
	if *keyFile != "" && *certFile != "" && *caFiles == "" {
		fmt.Println("Running key and certificate verification only")
		
		// 1. Validate key
		if err := validateKey(*keyFile); err != nil {
			fmt.Printf("❌ Key validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key is valid")

		// 2. Verify key and certificate match
		if err := verifyKeyCertMatch(*keyFile, *certFile); err != nil {
			fmt.Printf("❌ Key and certificate mismatch: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key matches certificate")
		
		return
	}

	// Option 3: only cert and cachain
	if *certFile != "" && *caFiles != "" && *keyFile == "" {
		fmt.Println("Running certificate chain validation only")
		
		// Verify certificate chain
		if err := verifyCertChain(*certFile, *caFiles); err != nil {
			fmt.Printf("❌ Certificate chain validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Certificate chain is valid")
		
		return
	}

	fmt.Println("Error: Invalid parameter combination")
	fmt.Println("Valid usage patterns:")
	fmt.Println("1. All parameters: -key KEY -cert CERT -cachain CA_CHAIN")
	fmt.Println("2. Key and cert only: -key KEY -cert CERT")
	fmt.Println("3. Cert and chain only: -cert CERT -cachain CA_CHAIN")
	flag.PrintDefaults()
	os.Exit(1)
}

func validateKey(keyFile string) error {
	keyData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return errors.New("failed to decode PEM key block")
	}

	var key crypto.PrivateKey
	var keyType string

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		keyType = "RSA"
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing PKCS8 key: %v", err)
		}
		if _, ok := key.(*rsa.PrivateKey); ok {
			keyType = "RSA"
		} else {
			return errors.New("only RSA keys are supported")
		}
	case "DSA PRIVATE KEY":
		return errors.New("DSA key validation is not implemented")
	default:
		return fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return fmt.Errorf("error parsing %s key: %v", keyType, err)
	}

	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		err = rsaKey.Validate()
		if err != nil {
			return fmt.Errorf("invalid RSA key: %v", err)
		}
	}

	return nil
}

func verifyKeyCertMatch(keyFile, certFile string) error {
	keyData, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %v", err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return errors.New("failed to decode PEM key block")
	}

	var key crypto.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			if _, ok := key.(*rsa.PrivateKey); !ok {
				return errors.New("only RSA keys are supported")
			}
		}
	default:
		return fmt.Errorf("unsupported key type: %s", keyBlock.Type)
	}

	if err != nil {
		return fmt.Errorf("error parsing key: %v", err)
	}

	certData, err := ioutil.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return errors.New("failed to decode PEM certificate block")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %v", err)
	}

	switch privKey := key.(type) {
	case *rsa.PrivateKey:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("certificate public key type doesn't match private key type")
		}

		if privKey.PublicKey.N.Cmp(pubKey.N) != 0 || privKey.PublicKey.E != pubKey.E {
			return errors.New("certificate public key doesn't match private key")
		}
	default:
		return errors.New("unsupported key type for verification")
	}

	return nil
}

func loadCACerts(caChainPaths string) ([]*x509.Certificate, error) {
	var caCerts []*x509.Certificate

	caFiles := strings.Split(caChainPaths, ",")
	for _, caFile := range caFiles {
		caFile = strings.TrimSpace(caFile)
		if caFile == "" {
			continue
		}

		caData, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file %s: %v", caFile, err)
		}

		for {
			block, rest := pem.Decode(caData)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				caCert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("error parsing CA certificate from %s: %v", caFile, err)
				}
				caCerts = append(caCerts, caCert)
			}
			caData = rest
		}
	}

	if len(caCerts) == 0 {
		return nil, errors.New("no CA certificates found in the chain")
	}

	return caCerts, nil
}

func verifyCertChain(certFile, caChainPaths string) error {
	certData, err := ioutil.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return errors.New("failed to decode PEM certificate block")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %v", err)
	}

	caCerts, err := loadCACerts(caChainPaths)
	if err != nil {
		return err
	}

	signedByChain := false
	for _, caCert := range caCerts {
		if cert.CheckSignatureFrom(caCert) == nil {
			signedByChain = true
			break
		}
	}

	if !signedByChain {
		return errors.New("certificate is not signed by any of the CA chain certificates")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()

	roots.AddCert(caCerts[len(caCerts)-1])

	if len(caCerts) > 1 {
		for _, caCert := range caCerts[:len(caCerts)-1] {
			intermediates.AddCert(caCert)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate is not valid for the specified chain: %v", err)
	}

	return nil
}