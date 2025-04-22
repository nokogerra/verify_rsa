package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	keyFile    string
	certFile   string
	caFiles    string
	noCertInfo bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "verify_rsa",
		Short: "Verify RSA keys and certificates",
		Long:  "Tool for validating RSA keys, certificate matching, and chain verification",
		Run: func(cmd *cobra.Command, args []string) {
			runVerification()
		},
	}

	// Flags
	rootCmd.Flags().StringVarP(&keyFile, "key", "k", "", "Path to private key file")
	rootCmd.Flags().StringVarP(&certFile, "cert", "c", "", "Path to certificate file (required)")
	rootCmd.Flags().StringVarP(&caFiles, "cachain", "a", "", "Comma-separated paths to CA chain files")
	rootCmd.Flags().BoolVar(&noCertInfo, "nocertinfo", false, "Skip detailed certificate output")

	// Sub-command for completion scripts gen
	var completionCmd = &cobra.Command{
		Use:   "completion [bash|zsh|powershell]",
		Short: "Generate shell completion scripts",
		Long: `To load completions:

Bash:
  $ source <(verify_rsa completion bash)

  # For permanent use:
  $ verify_rsa completion bash > /etc/bash_completion.d/verify_rsa

Zsh:
  $ source <(verify_rsa completion zsh)

  # For permanent use:
  $ verify_rsa completion zsh > /usr/local/share/zsh/site-functions/_verify_rsa

PowerShell:
  # For permanent use:
  PS> verify_rsa completion powershell | Out-String | Invoke-Expression
`,
		ValidArgs: []string{"bash", "zsh", "powershell"},
		Args:      cobra.ExactValidArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "powershell":
				cmd.Root().GenPowerShellCompletion(os.Stdout)
			default:
				fmt.Printf("Unsupported shell type: %s\n", args[0])
				os.Exit(1)
			}
		},
	}

	rootCmd.AddCommand(completionCmd)

	// --cert is a mandatory flag
	rootCmd.MarkFlagRequired("cert")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runVerification() {
    // Certificate details (if not omitted)
    if !noCertInfo {
        if err := printCertificateInfo(certFile); err != nil {
            fmt.Printf("❌ Failed to print certificate info: %v\n", err)
            os.Exit(1)
        }
    }

    // Option 1: all the params (key, cert and cachain)
    if keyFile != "" && certFile != "" && caFiles != "" {
        fmt.Println("\nRunning full verification (key, cert match, and chain validation)")
        
        // 1. Key check
        if err := validateKey(keyFile); err != nil {
            fmt.Printf("❌ Key validation failed: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("✅ Key is valid")

        // 2. Key and certificate match verification
        if err := verifyKeyCertMatch(keyFile, certFile); err != nil {
            fmt.Printf("❌ Key and certificate mismatch: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("✅ Key matches certificate")

        // 3. Certificate chain verification
        if err := verifyCertChain(certFile, caFiles); err != nil {
            fmt.Printf("❌ Certificate chain validation failed: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("✅ Certificate chain is valid")
        
        return
    }

    // Option 2: Only key and certificate
    if keyFile != "" && certFile != "" && caFiles == "" {
        fmt.Println("\nRunning key and certificate verification only")
        
        if err := validateKey(keyFile); err != nil {
            fmt.Printf("❌ Key validation failed: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("✅ Key is valid")

        if err := verifyKeyCertMatch(keyFile, certFile); err != nil {
            fmt.Printf("❌ Key and certificate mismatch: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("✅ Key matches certificate")
        
        return
    }

    // Option 3: Only certificate and chain
    if certFile != "" && caFiles != "" && keyFile == "" {
        fmt.Println("\nRunning certificate chain validation only")
        
        if err := verifyCertChain(certFile, caFiles); err != nil {
            fmt.Printf("❌ Certificate chain validation failed: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("✅ Certificate chain is valid")
        
        return
    }

    // If required parameter combinations are not specified
    fmt.Println("\nError: Invalid parameter combination")
    fmt.Println("Valid usage patterns:")
    fmt.Println("1. All parameters: -c (--cert=) CERT -k (--key=) KEY -a (--cachain=) CA_CHAIN")
    fmt.Println("2. Cert and key only: -c CERT -k KEY")
    fmt.Println("3. Cert and chain only: -c CERT -a CA_CHAIN")
	fmt.Println("--nocertinfo is optional")
    os.Exit(1)
}

func printCertificateInfo(certFile string) error {
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

	fmt.Println("\nCertificate Information:")
	fmt.Println("========================================")
	fmt.Printf("Subject: %s\n", cert.Subject.String())
	fmt.Printf("Issuer: %s\n", cert.Issuer.String())
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber.String())
	fmt.Printf("Valid From: %s\n", cert.NotBefore.Format(time.RFC3339))
	fmt.Printf("Valid Until: %s\n", cert.NotAfter.Format(time.RFC3339))
	fmt.Printf("Is CA: %t\n", cert.IsCA)

	// Print SANs
	if len(cert.DNSNames) > 0 {
		fmt.Println("\nSubject Alternative Names (DNS):")
		for _, dns := range cert.DNSNames {
			fmt.Printf("  - %s\n", dns)
		}
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Println("\nSubject Alternative Names (Email):")
		for _, email := range cert.EmailAddresses {
			fmt.Printf("  - %s\n", email)
		}
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Println("\nSubject Alternative Names (IP):")
		for _, ip := range cert.IPAddresses {
			fmt.Printf("  - %s\n", ip.String())
		}
	}
	if len(cert.URIs) > 0 {
		fmt.Println("\nSubject Alternative Names (URI):")
		for _, uri := range cert.URIs {
			fmt.Printf("  - %s\n", uri.String())
		}
	}

	// Print Key Usage
	fmt.Println("\nKey Usage:")
	if cert.KeyUsage != 0 {
		printKeyUsage(cert.KeyUsage)
	} else {
		fmt.Println("  No key usage specified")
	}

	// Print Extended Key Usage
	fmt.Println("\nExtended Key Usage:")
	if len(cert.ExtKeyUsage) > 0 {
		printExtendedKeyUsage(cert.ExtKeyUsage)
	} else {
		fmt.Println("  No extended key usage specified")
	}

	// Print Basic Constraints
	fmt.Println("\nBasic Constraints:")
	fmt.Printf("  Is CA: %t\n", cert.IsCA)
	if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
		fmt.Printf("  Max Path Length: %d\n", cert.MaxPathLen)
	}

	fmt.Println("========================================")
	return nil
}

func printKeyUsage(usage x509.KeyUsage) {
	usages := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Content Commitment"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}

	for _, u := range usages {
		if usage&u.bit != 0 {
			fmt.Printf("  - %s\n", u.name)
		}
	}
}

func printExtendedKeyUsage(extUsages []x509.ExtKeyUsage) {
	for _, extUsage := range extUsages {
		switch extUsage {
		case x509.ExtKeyUsageAny:
			fmt.Println("  - Any Usage")
		case x509.ExtKeyUsageServerAuth:
			fmt.Println("  - TLS Web Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			fmt.Println("  - TLS Web Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			fmt.Println("  - Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			fmt.Println("  - Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			fmt.Println("  - IPSec End System")
		case x509.ExtKeyUsageIPSECTunnel:
			fmt.Println("  - IPSec Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			fmt.Println("  - IPSec User")
		case x509.ExtKeyUsageTimeStamping:
			fmt.Println("  - Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			fmt.Println("  - OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			fmt.Println("  - Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			fmt.Println("  - Netscape Server Gated Crypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			fmt.Println("  - Microsoft Commercial Code Signing")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			fmt.Println("  - Microsoft Kernel Code Signing")
		default:
			fmt.Printf("  - Unknown Extended Key Usage (%d)\n", extUsage)
		}
	}
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
