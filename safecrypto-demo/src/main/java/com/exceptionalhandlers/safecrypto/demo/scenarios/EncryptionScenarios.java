package com.exceptionalhandlers.safecrypto.demo.scenarios;

import com.exceptionalhandlers.safecrypto.demo.ConsoleHelper;
import com.exceptionalhandlers.safecrypto.encryption.AesEncryptor;
import com.exceptionalhandlers.safecrypto.encryption.EncryptionException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

/** End-to-end demonstrations of {@link AesEncryptor}. */
public final class EncryptionScenarios {

  private static final String DEMO_PLAINTEXT = "this is a secret message";
  private static final SecureRandom RANDOM = new SecureRandom();

  private EncryptionScenarios() {}

  public static void encryptAndDecrypt(Scanner scanner) {
    ConsoleHelper.header("Scenario: Encrypt and decrypt a message");

    System.out.println("What we're doing:");
    System.out.println("  Encrypt a plaintext message and then decrypt it back to the");
    System.out.println("  original bytes using the same key.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  byte[] plaintext = \"" + DEMO_PLAINTEXT + "\".getBytes(UTF_8);");
    System.out.println("  String encrypted = AesEncryptor.encrypt(plaintext, key);");
    System.out.println("  byte[] decrypted = AesEncryptor.decrypt(encrypted, key);");
    System.out.println();

    byte[] key = randomKey();
    byte[] plaintext = DEMO_PLAINTEXT.getBytes(StandardCharsets.UTF_8);
    String encrypted = AesEncryptor.encrypt(plaintext, key);
    byte[] decrypted = AesEncryptor.decrypt(encrypted, key);

    System.out.println("Result:");
    System.out.println("  Encrypted: " + encrypted);
    System.out.println("  Decrypted: " + new String(decrypted, StandardCharsets.UTF_8));

    ConsoleHelper.pause(scanner);
  }

  public static void wrongKey(Scanner scanner) {
    ConsoleHelper.header("Scenario: Decrypt with the wrong key");

    System.out.println("What we're doing:");
    System.out.println("  Encrypt with one key, then attempt to decrypt with a different");
    System.out.println("  key.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  String encrypted = AesEncryptor.encrypt(plaintext, key);");
    System.out.println("  AesEncryptor.decrypt(encrypted, wrongKey);");
    System.out.println();

    byte[] key = randomKey();
    byte[] wrongKey = randomKey();
    byte[] plaintext = DEMO_PLAINTEXT.getBytes(StandardCharsets.UTF_8);
    String encrypted = AesEncryptor.encrypt(plaintext, key);

    System.out.println("Result:");
    try {
      AesEncryptor.decrypt(encrypted, wrongKey);
      System.out.println("  Decryption returned without throwing (unexpected!)");
    } catch (EncryptionException e) {
      System.out.println("  " + e.getClass().getSimpleName() + ": " + e.getMessage());
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  AES-GCM's authentication tag fails to verify under the wrong key,");
    System.out.println("  so decryption fails loudly rather than returning corrupted data.");

    ConsoleHelper.pause(scanner);
  }

  public static void tamperedCiphertext(Scanner scanner) {
    ConsoleHelper.header("Scenario: Tampered ciphertext rejection");

    System.out.println("What we're doing:");
    System.out.println("  Encrypt a message, flip a single byte in the ciphertext, and");
    System.out.println("  attempt to decrypt.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  String encrypted = AesEncryptor.encrypt(plaintext, key);");
    System.out.println("  // ... flip one byte in the ciphertext segment ...");
    System.out.println("  AesEncryptor.decrypt(tampered, key);");
    System.out.println();

    byte[] key = randomKey();
    byte[] plaintext = DEMO_PLAINTEXT.getBytes(StandardCharsets.UTF_8);
    String encrypted = AesEncryptor.encrypt(plaintext, key);
    String tampered = flipFirstCiphertextByte(encrypted);

    System.out.println("Result:");
    try {
      AesEncryptor.decrypt(tampered, key);
      System.out.println("  Decryption returned without throwing (unexpected!)");
    } catch (EncryptionException e) {
      System.out.println("  " + e.getClass().getSimpleName() + ": " + e.getMessage());
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  GCM's authentication tag is computed over the entire ciphertext.");
    System.out.println("  Any modification, even a single bit, causes verification to fail.");

    ConsoleHelper.pause(scanner);
  }

  public static void invalidKeyLength(Scanner scanner) {
    ConsoleHelper.header("Scenario: Reject invalid key length");

    System.out.println("What we're doing:");
    System.out.println("  Attempt to encrypt with a key that is not 16, 24, or 32 bytes.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  byte[] badKey = new byte[10];");
    System.out.println("  AesEncryptor.encrypt(plaintext, badKey);");
    System.out.println();

    byte[] badKey = new byte[10];
    byte[] plaintext = DEMO_PLAINTEXT.getBytes(StandardCharsets.UTF_8);

    System.out.println("Result:");
    try {
      AesEncryptor.encrypt(plaintext, badKey);
      System.out.println("  Encryption returned without throwing (unexpected!)");
    } catch (IllegalArgumentException e) {
      System.out.println("  " + e.getClass().getSimpleName() + ": " + e.getMessage());
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  The library validates the key length up front and rejects anything");
    System.out.println("  that is not a legal AES key size, before any crypto work runs.");

    ConsoleHelper.pause(scanner);
  }

  public static void ivUniqueness(Scanner scanner) {
    ConsoleHelper.header("Scenario: IV uniqueness");

    System.out.println("What we're doing:");
    System.out.println("  Encrypt the same plaintext twice with the same key, and compare");
    System.out.println("  the two encrypted payloads.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  String first = AesEncryptor.encrypt(plaintext, key);");
    System.out.println("  String second = AesEncryptor.encrypt(plaintext, key);");
    System.out.println();

    byte[] key = randomKey();
    byte[] plaintext = DEMO_PLAINTEXT.getBytes(StandardCharsets.UTF_8);
    String first = AesEncryptor.encrypt(plaintext, key);
    String second = AesEncryptor.encrypt(plaintext, key);

    System.out.println("Result:");
    System.out.println("  First:  " + first);
    System.out.println("  Second: " + second);
    System.out.println("  Equal:  " + first.equals(second));
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  Each encryption generates a fresh random IV, so identical inputs");
    System.out.println("  produce different ciphertexts. An observer cannot tell whether");
    System.out.println("  two encrypted values came from the same plaintext.");

    ConsoleHelper.pause(scanner);
  }

  private static byte[] randomKey() {
    byte[] key = new byte[32];
    RANDOM.nextBytes(key);
    return key;
  }

  /** Flips the first byte of the ciphertext segment, leaving the IV segment unchanged. */
  private static String flipFirstCiphertextByte(String encrypted) {
    String[] parts = encrypted.split(":", 2);
    byte[] ciphertext = Base64.getDecoder().decode(parts[1]);
    ciphertext[0] ^= (byte) 0xFF;
    return parts[0] + ":" + Base64.getEncoder().encodeToString(ciphertext);
  }
}
