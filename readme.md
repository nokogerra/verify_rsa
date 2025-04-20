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