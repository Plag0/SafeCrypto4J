package com.exceptionalhandlers.safecrypto.demo;

import com.exceptionalhandlers.safecrypto.demo.scenarios.ComparisonScenarios;
import com.exceptionalhandlers.safecrypto.demo.scenarios.EncryptionScenarios;
import com.exceptionalhandlers.safecrypto.demo.scenarios.PasswordScenarios;
import java.util.Scanner;

/** Entry point for the SafeCrypto4J interactive demo. */
public final class DemoApp {

  private DemoApp() {}

  public static void main(String[] args) {
    try (Scanner scanner = new Scanner(System.in)) {
      printIntro();

      Menu passwordMenu =
          new Menu("Password hashing scenarios", "Back", scanner)
              .add("Hash and verify a password", () -> PasswordScenarios.hashAndVerify(scanner))
              .add("Verify with the wrong password", () -> PasswordScenarios.wrongPassword(scanner))
              .add("Verify with a tampered hash", () -> PasswordScenarios.tamperedHash(scanner))
              .add("Verify with malformed input", () -> PasswordScenarios.malformedInput(scanner))
              .add("Show salt uniqueness", () -> PasswordScenarios.saltUniqueness(scanner));

      Menu encryptionMenu =
          new Menu("Encryption scenarios", "Back", scanner)
              .add(
                  "Encrypt and decrypt a message",
                  () -> EncryptionScenarios.encryptAndDecrypt(scanner))
              .add("Decrypt with the wrong key", () -> EncryptionScenarios.wrongKey(scanner))
              .add(
                  "Decrypt tampered ciphertext",
                  () -> EncryptionScenarios.tamperedCiphertext(scanner))
              .add("Reject invalid key length", () -> EncryptionScenarios.invalidKeyLength(scanner))
              .add("Show IV uniqueness", () -> EncryptionScenarios.ivUniqueness(scanner));

      new Menu("SafeCrypto4J Demo", "Exit", scanner)
          .add("Compare naive Java crypto vs SafeCrypto4J", () -> ComparisonScenarios.run(scanner))
          .add("Password hashing scenarios", passwordMenu::show)
          .add("Encryption scenarios", encryptionMenu::show)
          .show();

      System.out.println();
      System.out.println("Goodbye.");
    }
  }

  private static void printIntro() {
    System.out.println();
    System.out.println("Welcome to the SafeCrypto4J demo.");
    System.out.println();
    System.out.println("This demo walks through correct usage of the library and shows how it");
    System.out.println("prevents common cryptographic mistakes. Pick a scenario to begin.");
  }
}
