package com.exceptionalhandlers.safecrypto.demo.scenarios;

import com.exceptionalhandlers.safecrypto.demo.ConsoleHelper;
import java.util.Scanner;

/**
 * Side-by-side comparison of common Java crypto mistakes and the equivalent SafeCrypto4J code. The
 * unsafe snippets are printed as text and never executed.
 */
public final class ComparisonScenarios {

  private ComparisonScenarios() {}

  public static void run(Scanner scanner) {
    ConsoleHelper.header("Naive Java crypto vs SafeCrypto4J");

    System.out.println("Below are common mistakes a developer might make using");
    System.out.println("standard Java crypto APIs, alongside the equivalent");
    System.out.println("SafeCrypto4J code.");

    ConsoleHelper.subheader("Password storage: unsafe");
    System.out.println();
    System.out.println("  MessageDigest md = MessageDigest.getInstance(\"MD5\");");
    System.out.println("  byte[] hash = md.digest(password.getBytes());");
    System.out.println();
    System.out.println("  Problems:");
    System.out.println("    - MD5 is cryptographically broken");
    System.out.println("    - No salt, so identical passwords produce identical hashes");
    System.out.println("    - No work factor, so brute-force attacks run at full speed");

    ConsoleHelper.subheader("Password storage: safe");
    System.out.println();
    System.out.println("  String stored = PasswordHasher.hashPassword(password);");
    System.out.println();
    System.out.println("  SafeCrypto4J handles:");
    System.out.println("    - PBKDF2 with HMAC-SHA256");
    System.out.println("    - 16-byte cryptographically random salt per password");
    System.out.println("    - 600,000 iteration work factor");

    ConsoleHelper.subheader("Symmetric encryption: unsafe");
    System.out.println();
    System.out.println("  Cipher cipher = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");");
    System.out.println("  cipher.init(Cipher.ENCRYPT_MODE, key);");
    System.out.println("  byte[] ciphertext = cipher.doFinal(plaintext);");
    System.out.println();
    System.out.println("  Problems:");
    System.out.println("    - ECB mode leaks patterns in the plaintext");
    System.out.println("    - No integrity check, so ciphertext can be silently tampered with");
    System.out.println("    - No IV used at all");

    ConsoleHelper.subheader("Symmetric encryption: safe");
    System.out.println();
    System.out.println("  String encrypted = AesEncryptor.encrypt(plaintext, key);");
    System.out.println();
    System.out.println("  SafeCrypto4J handles:");
    System.out.println("    - AES-GCM authenticated encryption");
    System.out.println("    - Fresh random 12-byte IV per call");
    System.out.println("    - GCM authentication tag detects tampered ciphertext");

    ConsoleHelper.pause(scanner);
  }
}
