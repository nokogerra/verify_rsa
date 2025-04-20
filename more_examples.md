## More Examples  

### Trivia:  
- **rootca** is self-signed.  
- **subca** was signed by **rootca**.  
- The **certificate** was signed by **subca**, and **key.key** is the certificate’s private key.  
- **wrong_certificate** was signed by an unrelated CA.  

### Verification Examples  

#### Full Verification (Certificate, Key and Chain)  
```bash
$ verify_rsa -c certificate.crt -k key.key -a cachain.crt --nocertinfo 

Running full verification (key, cert match, and chain validation)
✅ Key is valid
✅ Key matches certificate
✅ Certificate chain is valid
```

#### Full Verification with Split CA Chain  
```bash
$ verify_rsa -c certificate.crt -k key.key -a subca.crt,rootca.crt --nocertinfo 

Running full verification (key, cert match, and chain validation)
✅ Key is valid
✅ Key matches certificate
✅ Certificate chain is valid 
```

#### Missing Intermediate CA (Chain Validation Fails)  
```bash
$ verify_rsa -c certificate.crt -k key.key -a rootca.crt --nocertinfo 

Running full verification (key, cert match, and chain validation)
✅ Key is valid
✅ Key matches certificate
❌ Certificate chain validation failed: certificate is not signed by any of the CA chain certificates 
```

#### Key and Certificate Verification Only  
```bash
$ verify_rsa -c certificate.crt -k key.key --nocertinfo 

Running key and certificate verification only
✅ Key is valid
✅ Key matches certificate
```

#### Key and Certificate Mismatch  
```bash
$ verify_rsa -c wrong_certificate.crt -k key.key --nocertinfo 

Running key and certificate verification only
✅ Key is valid
❌ Key and certificate mismatch: certificate public key doesn't match private key  
```

#### Invalid Certificate Chain (Wrong Issuer)  
```bash
$ verify_rsa -c wrong_certificate.crt -a cachain.crt --nocertinfo 

Running certificate chain validation only
❌ Certificate chain validation failed: certificate is not signed by any of the CA chain certificates
```

#### CA Chain Validation (Order-Independent)  
```bash
$ verify_rsa -c certificate.crt -a rootca.crt,subca.crt --nocertinfo 

Running certificate chain validation only
✅ Certificate chain is valid 

# OpenSSL equivalent (order does not matter):  
$ openssl verify -CAfile <(cat rootca.crt subca.crt) certificate.crt  
certificate.crt: OK  
```

#### SubCA and RootCA Validation  
```bash
# Valid: SubCA is signed by RootCA  
$ verify_rsa -c subca.crt -a rootca.crt --nocertinfo 

Running certificate chain validation only
✅ Certificate chain is valid

# Invalid: RootCA is self-signed, not by SubCA  
$ verify_rsa -c rootca.crt -a subca.crt --nocertinfo 

Running certificate chain validation only
❌ Certificate chain validation failed: certificate is not signed by any of the CA chain certificates

# Valid: RootCA is self-signed  
$ verify_rsa -c rootca.crt -a rootca.crt --nocertinfo 

Running certificate chain validation only
✅ Certificate chain is valid
```
