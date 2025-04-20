## Verify RSA Key/Certificate Pair and CA Chain Validity  

I don’t write in Go, so this tool is primarily the result of my collaboration with DeepSeek. It is a small utility that can:  

- **Check RSA key consistency** (similar to `openssl rsa -check`).  
- **Verify if an RSA key matches a certificate** by comparing their modulus values.  
- **Validate the certificate chain** to confirm the certificate was issued by the specified CA chain (similar to `openssl verify`).  

### Usage  

Run the binary without parameters to display the help menu:

```sh
Error: required flag(s) "cert" not set
Usage:
  verify_rsa [flags]
  verify_rsa [command]

Available Commands:
  completion  Generate shell completion scripts
  help        Help about any command

Flags:
  -a, --cachain string   Comma-separated paths to CA chain files
  -c, --cert string      Path to certificate file (required)
  -h, --help             help for verify_rsa
  -k, --key string       Path to private key file
      --nocertinfo       Skip detailed certificate output

Use "verify_rsa [command] --help" for more information about a command.

required flag(s) "cert" not set
```

You must provide one of the following parameter combinations:  

1. **`-c` (--cert),`-k` (--key) and `-a` (--cachain)**:  
   - Checks key consistency, verifies key-certificate match, and validates the CA chain.
2. **`-c` and `-k`**:  
   - Checks key consistency and verifies key-certificate match.  
3. **`-c` and `-a`**:  
   - Validates the certificate against the CA chain.</br>

Use **`--nocertinfo`** to omit displaying the certificate details.

### Examples  
It's implied that "verify_rsa" is in $PATH dir.</br>
**Full Verification (Certificate, Key and Chain):**
```sh
$ verify_rsa -c certificate.crt -k key.key -a cachain.crt 

Certificate Information:
========================================
Subject: CN=s1-nginx01.nokogerra.lab,O=NOKOGERRA-LAB,ST=Moscow,C=RU
Issuer: CN=s1-sub-ca-01,O=NOKOGERRA-LAB,C=RU
Serial Number: 46751226600568542060910718435780266934608242650
Valid From: 2025-04-20T10:08:18Z
Valid Until: 2026-04-20T10:08:18Z
Is CA: false

Subject Alternative Names (DNS):
  - s1-nginx01.nokogerra.lab

Subject Alternative Names (IP):
  - 10.215.102.21

Key Usage:
  - Digital Signature
  - Key Encipherment

Extended Key Usage:
  - TLS Web Client Authentication
  - TLS Web Server Authentication

Basic Constraints:
  Is CA: false
========================================

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

**Key-Certificate Mismatch:**
```sh
$ verify_rsa --cert=wrong_certificate.crt --key key.key --cachain cachain.crt --nocertinfo 

Running full verification (key, cert match, and chain validation)
✅ Key is valid
❌ Key and certificate mismatch: certificate public key doesn't match private key 
```

**Key and Certificate Verification Only:**  
```sh
verify_rsa --cert=certificate.crt --key key.key --nocertinfo 

Running key and certificate verification only
✅ Key is valid
✅ Key matches certificate 
```

**Certificate Chain Validation Only:**  
```sh
$ verify_rsa --cert=certificate.crt -a cachain.crt --nocertinfo 

Running certificate chain validation only
✅ Certificate chain is valid
```

For more examples, visit [this page](more_examples.md).

### Shell Completion
Pre-built binaries have platform and architecture in their names (build script ./build.sh works the same way), but the completion scripts are generated for "verify_rsa" binary, so **don't forget to rename the binary**.</br>
There are a few examples of making shell-completion scripts.
```sh
# bash for the current session only 
source <(verify_rsa completion bash)

# bash permanent (requires sudo/root)
sudo bash -c "verify_rsa completion bash > /etc/bash_completion.d/verify_rsa"

# zsh for the current session only (NOT TESTED)
source <(verify_rsa completion zsh)

# zsh permanent  (NOT TESTED)
verify_rsa completion zsh > ~/.zsh/completions/_verify_rsa
verify_rsa completion zsh > /usr/local/share/zsh/site-functions/_verify_rsa

# Powershell permanent (NOT TESTED)
verify_rsa completion powershell | Out-String | Invoke-Expression
```
### Build  

You can either download a pre-built binary from this project or compile it yourself. For example:  
```sh
./build.sh  
```
In case you want to drop go.mod and go.sum:
```sh
go mod init github.com/yourusername/verify_rsa
go mod tidy
```
go.mod requirements:
```sh
require (
	github.com/spf13/cobra v1.8.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
)
```
Cobra is needed to make shell-completion scripts.
