## More Examples  

### Trivia:  
- **rootca** is self-signed.  
- **subca** was signed by **rootca**.  
- The **certificate** was signed by **subca**, and **key.key** is the certificate’s private key.  
- **wrong_certificate** was signed by an unrelated CA.  

### Verification Examples  

#### Full Verification (Key, Certificate, and Chain)  
```bash
$ verify_rsa -key key.key -cert certificate.crt -cachain cachain.crt  
Running full verification (key, cert match, and chain validation)  
✅ Key is valid  
✅ Key matches certificate  
✅ Certificate chain is valid  
```

#### Full Verification with Split CA Chain  
```bash
$ verify_rsa -key key.key -cert certificate.crt -cachain subca.crt,rootca.crt  
Running full verification (key, cert match, and chain validation)  
✅ Key is valid  
✅ Key matches certificate  
✅ Certificate chain is valid  
```

#### Missing Intermediate CA (Chain Validation Fails)  
```bash
$ verify_rsa -key key.key -cert certificate.crt -cachain rootca.crt  
Running full verification (key, cert match, and chain validation)  
✅ Key is valid  
✅ Key matches certificate  
❌ Certificate chain validation failed: Certificate is not signed by any of the provided CA chain certificates  
```

#### Key and Certificate Verification Only  
```bash
$ verify_rsa -key key.key -cert certificate.crt  
Running key and certificate verification only  
✅ Key is valid  
✅ Key matches certificate  
(No chain validation performed)  
```

#### Key and Certificate Mismatch  
```bash
$ verify_rsa -key key.key -cert wrong_certificate.crt  
Running key and certificate verification only  
✅ Key is valid  
❌ Key and certificate mismatch: Certificate public key does not match private key  
```

#### Invalid Certificate Chain (Wrong Issuer)  
```bash
$ verify_rsa -cert wrong_certificate.crt -cachain cachain.crt  
Running certificate chain validation only  
❌ Certificate chain validation failed: Certificate is not signed by any of the provided CA chain certificates  
```

#### CA Chain Validation (Order-Independent)  
```bash
$ verify_rsa -cert certificate.crt -cachain rootca.crt,subca.crt  
Running certificate chain validation only  
✅ Certificate chain is valid  

# OpenSSL equivalent (order does not matter):  
$ openssl verify -CAfile <(cat rootca.crt subca.crt) certificate.crt  
certificate.crt: OK  
```

#### SubCA and RootCA Validation  
```bash
# Valid: SubCA is signed by RootCA  
$ verify_rsa -cert subca.crt -cachain rootca.crt  
Running certificate chain validation only  
✅ Certificate chain is valid  

# Invalid: RootCA is self-signed, not by SubCA  
$ verify_rsa -cert rootca.crt -cachain subca.crt  
Running certificate chain validation only  
❌ Certificate chain validation failed: Certificate is not signed by any of the provided CA chain certificates  

# Valid: RootCA is self-signed  
$ verify_rsa -cert rootca.crt -cachain rootca.crt  
Running certificate chain validation only  
✅ Certificate chain is valid  
```
