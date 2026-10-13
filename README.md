# SafeCrypto4J

A misuse-resistant Java security toolkit for common security tasks.

SafeCrypto4J wraps the standard Java cryptography APIs in a small, opinionated interface. It picks safe algorithms and parameters for you, validates everything you pass in and refuses risky options, so that the easy way to use it is also the correct way. It does not implement any cryptography itself.

| Module | Task | Built on |
|---|---|---|
| `PasswordHasher` | Store and verify passwords | PBKDF2-HMAC-SHA256, 600,000 iterations, random 16-byte salt |
| `AesEncryptor` | Encrypt and decrypt data | AES-GCM with a random 12-byte IV per encryption |
| `HmacIntegrity` | Detect tampering with data | HMAC with SHA-512 by default (SHA-256 and SHA-384 also allowed) |

An interactive demo shows each module in use, including what happens when things go wrong.

## Requirements

- Java 17 or later
- Apache Maven 3.9 or later (to build from source)

## Building

```bash
git clone https://github.com/Plag0/SafeCrypto4J.git
cd SafeCrypto4J
git checkout v1.0.0   # optional: build a specific release
mvn verify
```

`mvn verify` compiles everything, runs all tests, checks formatting and builds the jars:

| File | What it is |
|---|---|
| `safecrypto-core/target/safecrypto-core-1.0.0.jar` | The library |
| `safecrypto-core/target/safecrypto-core-1.0.0-sources.jar` | Library source, for IDEs |
| `safecrypto-core/target/safecrypto-core-1.0.0-javadoc.jar` | Library API documentation |
| `safecrypto-demo/target/safecrypto-demo.jar` | The runnable demo, with the library included |

To use the library in another Maven project, run `mvn install` and add:

```xml
<dependency>
  <groupId>com.exceptionalhandlers</groupId>
  <artifactId>safecrypto-core</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Running the demo

```bash
java -jar safecrypto-demo/target/safecrypto-demo.jar
```

The demo compares naive Java crypto code with the SafeCrypto4J equivalent, then walks through password hashing, encryption and HMAC integrity scenarios, including wrong keys, tampered data and rejected input.

## Using the modules

### Password hashing

`PasswordHasher` protects stored passwords by salting them and hashing them slowly. Each hash uses a random 16-byte salt, 600,000 PBKDF2 iterations and a 256-bit output.

```java
char[] password = getPasswordFromUser();
String stored = PasswordHasher.hashPassword(password);
Arrays.fill(password, '\0');

char[] attempt = getPasswordFromUser();
boolean ok = PasswordHasher.verifyPassword(attempt, stored);
Arrays.fill(attempt, '\0');
```

Store the whole returned string. Its format is `iterations:base64Salt:base64Hash`, so it records everything needed to verify a password later, and the password itself is never stored.

`verifyPassword` returns `false` for a wrong password and throws `IllegalArgumentException` if the stored value is malformed or has been tampered with, including an iteration count below 100,000 or above 10,000,000.

### Encryption

`AesEncryptor` encrypts data with AES-GCM, which also detects any change to the encrypted data.

```java
byte[] key = AesEncryptor.generateKey(); // or load an existing key from a secret store
byte[] plaintext = "Sensitive data".getBytes(StandardCharsets.UTF_8);

String encrypted = AesEncryptor.encrypt(plaintext, key);
byte[] decrypted = AesEncryptor.decrypt(encrypted, key);

Arrays.fill(plaintext, (byte) 0);
Arrays.fill(key, (byte) 0);
```

`generateKey()` returns a random 256-bit key. Keys of 16, 24 or 32 bytes are accepted; anything else is rejected.

`encrypt()` returns a string in the format `base64IV:base64Ciphertext`, which is safe to store in a text file or database column. Only the key needs to be kept secret. `decrypt()` throws `EncryptionException` if the key is wrong or the data has been modified.

### Integrity

`HmacIntegrity` produces a tag that proves a message has not been altered by anyone who lacks the key. It does not hide the message.

```java
try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
  byte[] message = "important data".getBytes(StandardCharsets.UTF_8);
  byte[] tag = HmacIntegrity.sign(key, message);

  if (!HmacIntegrity.verify(key, message, tag)) {
    throw new SecurityException("Invalid HMAC");
  }
}
```

- `generateKey()` returns a random 64-byte key. `HmacIntegrity.Key.of(bytes)` loads existing key material, which must be at least 32 bytes.
- Close keys when you are done, ideally with try-with-resources as above. Closing overwrites the key material, and a closed key cannot be used again.
- `sign()` and `verify()` use HMAC-SHA512 unless you pass an algorithm: `HmacIntegrity.sign(key, message, HmacIntegrity.Algorithm.SHA256)`.
- Tags are raw bytes. To store one as text, encode it with `Base64.getEncoder().encodeToString(tag)`. A tag does not record which algorithm made it, so always verify with the algorithm you signed with.
- `verify()` returns `false` for a tag that does not match, and throws `IllegalArgumentException` for a tag of the wrong length, because that means the tag is malformed rather than merely wrong.

## Handling errors

The library uses three outcomes consistently:

| Outcome | Meaning | Examples |
|---|---|---|
| `false` | The inputs were valid, but they did not match | Wrong password, tampered message or tag |
| `IllegalArgumentException` | Your input was invalid or malformed | `null` arguments, wrong key length, corrupt stored hash or payload |
| `SafeCryptoException` | The operation itself failed | Decryption with the wrong key or of tampered data, a closed HMAC key, an algorithm missing from the JVM |

`SafeCryptoException` is the parent of `PasswordHashingException`, `EncryptionException` and `IntegrityException`, so one `catch` handles all three. Exception messages never contain passwords, keys or plaintext, so they are safe to log.

## Security notes

### Threat model

SafeCrypto4J assumes the JVM it runs in, and the machine underneath, are trusted. Within that assumption it protects against:

- Stolen password databases. Salts defeat precomputed tables, and the slow hash makes guessing each password expensive.
- Tampered stored data. AES-GCM and HMAC detect any modification, and malformed values are rejected rather than half-processed.
- Downgraded or inflated work factors. A stored hash edited to use too few, or absurdly many, iterations is rejected.
- Timing attacks on password and tag comparison, which run in constant time.
- Developer mistakes, such as weak algorithms, reused IVs, short keys and truncated tags, which the API does not allow.

It does **not** protect against:

- A compromised host. Code running in the same JVM can read keys and passwords from memory.
- Poor key management. If a key is leaked, everything protected by it is exposed. See below.
- Weak passwords. A slow hash only delays guessing; it cannot make `password123` safe. Enforce a password policy separately.
- Replay. A valid encrypted value or signed message can be resent or copied. Include a timestamp, counter or record ID inside the data if that matters.
- Swapped records. Encrypted values and tags are not tied to where they are stored, so an attacker who can write to your database could swap two of them without detection.
- Data in transit. Use TLS when sending data over a network.

### Your responsibilities for keys

The library generates good keys, but storing and managing them is up to you:

- Never put keys in source code or commit them to version control. Load them at runtime from a secret manager, an operating system key store or an environment variable that is set outside the codebase.
- Use a separate key for each purpose. Do not use the same bytes as both an AES key and an HMAC key.
- Rotate keys. Replace keys if they may have been exposed, and in any case well before 4 billion encryptions under one AES key, the safe limit for random IVs.
- Keep keys out of logs, error messages and crash reports.
- Clear key and password arrays with `Arrays.fill` once you have finished with them, and close `HmacIntegrity.Key` objects.

### Common mistakes to avoid

| Mistake | Instead |
|---|---|
| Hashing passwords with plain SHA-256 or MD5 | `PasswordHasher.hashPassword` |
| Storing a password in a `String` | Keep it in a `char[]` and clear it after use |
| Writing a key as a string literal, such as `"MySecretKey12345".getBytes()` | `AesEncryptor.generateKey()` or `HmacIntegrity.generateKey()`, stored in a secret store |
| Encrypting without checking for tampering, such as AES-ECB or AES-CBC alone | `AesEncryptor`, which uses authenticated AES-GCM |
| Checking integrity with a plain hash of the data | `HmacIntegrity`, which requires the secret key |
| Comparing secrets with `Arrays.equals` or `String.equals` | The library's `verify` methods, which compare in constant time |
| Treating `false` and exceptions the same way | Return 'access denied' for `false`; investigate exceptions, which point to bad input or tampering |

## Contributing

Changes go through pull requests against `main`, and each one is reviewed by another team member before merging. CI runs `mvn verify` on every pull request, so tests, Javadoc and formatting must all pass. Format code before committing with:

```bash
mvn spotless:apply
```

New security-relevant behaviour needs tests for both the success case and the failure cases (wrong key, tampered data, invalid input).

## Licence

SafeCrypto4J is released under the [MIT License](LICENSE). It is provided as is, without warranty of any kind.
