# SafeCrypto4J

A misuse-resistant Java security toolkit for common security tasks.

SafeCrypto4J provides a few focused modules that handle common cryptographic details safely by default, including features such as:

- Password hashing with PBKDF2-HMAC-SHA256.
- Random salts for every password hash.
- Minimum password-hashing work-factor enforcement.
- Constant-time password verification.
- AES-GCM authenticated encryption.
- Random IV generation for every encryption operation.
- Validation of keys, ciphertexts, salts, hashes, and encoded payloads.
- HMAC integrity tag signing and verification.
- An interactive demo showing both correct usage and common failure cases.

# Requirements
- Java 17
- Apache Maven

# Building the project
Clone this repository. Optionally checkout a specific release version. Then run the tests.

```bash
git clone https://github.com/Plag0/SafeCrypto4J.git
git checkout vSOME_STABLE_VERSION # optional
cd SafeCrypto4J
mvn verify
```

This runs all tests for all modules. If you wish to build a usable `.jar`, run `mvn package` instead.

# Run the cli demo
After building the project you can run the demo to check out some of the functionality:

```bash
java -jar safecrypto-demo/target/safecrypto-demo.jar
```

The demo includes various comparisons between naive Java crypto and using SafeCrypto4J, as well as demonstrations of encryption and password hashing.

# Using the modules
## Password hashing
`PasswordHasher` protects passwords by salting and hashing them.

Hashes use:
- A random 16-byte salt.
- 600000 PBKDF2 iterations.
- A 256-bit hash.

Stored hashes use the format: `iterations:base64Salt:base64Hash`

To use this module, call `PasswordHasher.hashPassword()` and store the resulting hash. Then, to verify call `PasswordHasher.verifyPassword()`.

```java
char[] password = getPasswordFromUser();
String stored = PasswordHasher.hashPassword(password);
Arrays.fill(password, '\0');

char[] attempt = getPasswordFromUser();
boolean ok = PasswordHasher.verifyPassword(attempt, stored);
Arrays.fill(attempt, '\0');
```

`verifyPassword` returns true when the password matches, and false when the inputs are valid but the password doesn't match. If the hash is invalid `verifyPassword` will throw.

## Encryption

`AesEncryptor` encrypts your data with AES.

The supported key sizes are 16, 24, and 32 bytes.

The stored payload format is `base64IV:base64Ciphertext`.

To use this module, first decide on your key, and then call `encrypt()` and `decrypt()`.

```java
byte[] key = getKeyFromSecureSource();
byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);

String encrypted = AesEncryptor.encrypt(plaintext, key);

byte[] decrypted = AesEncryptor.decrypt(encrypted, key);

Arrays.fill(plaintext, (byte) 0);
Arrays.fill(key, (byte) 0);
```

`encrypt()` returns a string, so it's safe to store an encrypted payload inside a text file or plain-text networked message.

## Integrity

`HmacIntegrity` signs your data with a key to provide verifiable integrity.

The supported hashing algorithms are SHA256, SHA384, and SHA512

Keys must be larger than 32 bytes as a safety measure.

To use this module, first generate a key with `generateKey()`.

Use the key to `sign()` a message, and store the resulting tag. Later, verify the message with `verify()`.

```java
try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
  byte[] message = "important data 👩‍❤️‍👩️".getBytes(StandardCharsets.UTF_8);
  byte[] tag = HmacIntegrity.sign(key, message);

  if (!HmacIntegrity.verify(key, message, tag)) {
    throw new SecurityException("Invalid HMAC");
  }
}
```

Ensure that you close your key after use with Key.close(), alternatively you can use a try-with-resources block to auto-close the key.
