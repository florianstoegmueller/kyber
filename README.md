# Kyber
Encryption system utilizing the Kyber KEM.   
This application can be used to generate a Kyber keypair and to encrypt and decrypt a shared secret ("key").

### Usage

The application supports three modes:

* Generation: This mode generates a secret-key and a public-key file.
  ```bash
  ./kyber -g -uid <mail> [-pass <aes-key>]
  ```
* Encryption: Taking a public-key file as input this mode genereates a shared secret and ouputs it as a ciphertext (and also unencrypted).
  ```bash
  ./kyber -e -pk <pk-file>
  ```
* Decryption: The decryption mode needs a secret-key file and a ciphertext file to retrive the shared secret.
  ```bash
  ./kyber -d -sk <sk-file> -ct <ct-file> [-pass <aes-key>]
  ```
With the optional option `-pass` the secret key file can be encrypted using AES.

### Building

To build this project CMake and OPENSSL is requiered.
By typing the following command the project can be built:
```bash
make release
```
