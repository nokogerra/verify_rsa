# Verify RSA key/certificate pair and CA chain validity
I don't write in GO, so it's primarily a result of my interaction with DeepSeek.
This is a small tool, which can:
- check an RSA key consistency (similar to "openssl rsa -check");
- check if and RSA key matches the certificate (comparing their modulus);
- check if the certificate chain is valid, in other words it checks if the certificate was issued by a CA chain (similar to "openssl verify");
### Usage
Run the binary (or script with "go run verify_rsa.go") without params to get the help:
```
verify_rsa
Error: -cert parameter is required
  -cachain string
        Comma-separated paths to CA chain files (subca.pem,rootca.pem) or to a single file
  -cert string
        Path to certificate file
  -key string
        Path to private key file
```
You have to provide a few params to this tool, and there are three valid param sets:
- -key, -cert and -cachain: checks the key consistency, if the key matches the certificate and if the certificate was issued by the CA chain;
- -key and -cert: checks the key consistency and if the key matches the certificate;
- -cert and -cachain: checks if the certificate was issued by the CA chain.
Here are a few examples:
```
$ verify_rsa -key key.key -cert certificate.crt -cachain cachain.crt 
Running full verification (key, cert match, and chain validation)
✅ Key is valid
✅ Key matches certificate
✅ Certificate chain is valid
$ verify_rsa -key key.key -cert wrong_certificate.crt -cachain cachain.crt 
Running full verification (key, cert match, and chain validation)
✅ Key is valid
❌ Key and certificate mismatch: certificate public key doesn't match private key
$ verify_rsa -key key.key -cert certificate.crt 
Running key and certificate verification only
✅ Key is valid
✅ Key matches certificate
$ verify_rsa -cert certificate.crt -cachain cachain.crt 
Running certificate chain validation only
✅ Certificate chain is valid
```
More examples at [this page](more_examples.md)
### Build
You can get a binary in this project and put it where you want in you system, or you can build it, e.g.:
```
go version
go version go1.24.2 linux/amd64
go mod init verify_rsa
go mod tidy
./build.sh
```





Here’s an improved version of your text with better clarity, grammar, and flow while maintaining all the key details:

---

### Verify RSA Key/Certificate Pair and CA Chain Validity  

I don’t write in Go, so this tool is primarily the result of my collaboration with DeepSeek. It is a small utility that can:  

- **Check RSA key consistency** (similar to `openssl rsa -check`).  
- **Verify if an RSA key matches a certificate** by comparing their modulus values.  
- **Validate the certificate chain** to confirm the certificate was issued by the specified CA chain (similar to `openssl verify`).  

### Usage  

Run the binary (or script with `go run verify_rsa.go`) without parameters to display the help menu:  

```sh
verify_rsa  
Error: -cert parameter is required  
  -cachain string  
        Comma-separated paths to CA chain files (e.g., subca.pem,rootca.pem) or a single file  
  -cert string  
        Path to the certificate file  
  -key string  
        Path to the private key file  
```

You must provide one of the following parameter combinations:  

1. **`-key`, `-cert`, and `-cachain`**:  
   - Checks key consistency, verifies key-certificate match, and validates the CA chain.  
2. **`-key` and `-cert`**:  
   - Checks key consistency and verifies key-certificate match.  
3. **`-cert` and `-cachain`**:  
   - Validates the certificate against the CA chain.  

### Examples  

**Full Verification (Key, Certificate, and Chain):**  
```sh
$ verify_rsa -key key.key -cert certificate.crt -cachain cachain.crt  
Running full verification (key, cert match, and chain validation)  
✅ Key is valid  
✅ Key matches certificate  
✅ Certificate chain is valid  
```

**Key-Certificate Mismatch:**  
```sh
$ verify_rsa -key key.key -cert wrong_certificate.crt -cachain cachain.crt  
Running full verification (key, cert match, and chain validation)  
✅ Key is valid  
❌ Key and certificate mismatch: certificate public key doesn't match private key  
```

**Key and Certificate Verification Only:**  
```sh
$ verify_rsa -key key.key -cert certificate.crt  
Running key and certificate verification only  
✅ Key is valid  
✅ Key matches certificate  
```

**Certificate Chain Validation Only:**  
```sh
$ verify_rsa -cert certificate.crt -cachain cachain.crt  
Running certificate chain validation only  
✅ Certificate chain is valid  
```

For more examples, visit [this page](more_examples.md).  

### Build  

You can either download a pre-built binary from this project or compile it yourself. For example:  

```sh
go version  
go version go1.24.2 linux/amd64  
go mod init verify_rsa  
go mod tidy  
./build.sh  
```
