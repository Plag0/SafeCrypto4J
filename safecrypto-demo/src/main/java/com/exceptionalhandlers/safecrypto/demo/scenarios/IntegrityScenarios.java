package com.exceptionalhandlers.safecrypto.demo.scenarios;

import com.exceptionalhandlers.safecrypto.demo.ConsoleHelper;
import com.exceptionalhandlers.safecrypto.integrity.HmacIntegrity;
import com.exceptionalhandlers.safecrypto.integrity.IntegrityException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/** End-to-end demonstrations of {@link HmacIntegrity}. */
public final class IntegrityScenarios {

  private static final String DEMO_MESSAGE = "transfer $100 to account 12345";
  private static final String TAMPERED_MESSAGE = "transfer $900 to account 12345";

  private static final int SHORT_KEY_LENGTH = 16;

  private static final int TRUNCATED_TAG_LENGTH = 8;

  private IntegrityScenarios() {}

  public static void signAndVerify(Scanner scanner) {
    ConsoleHelper.header("Scenario: Sign and verify a message");

    System.out.println("What we're doing:");
    System.out.println("  Generate a key, sign a message with it, then verify the message");
    System.out.println("  against the tag using the same key.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {");
    System.out.println("    byte[] message = \"" + DEMO_MESSAGE + "\".getBytes(UTF_8);");
    System.out.println("    byte[] tag = HmacIntegrity.sign(key, message);");
    System.out.println("    boolean ok = HmacIntegrity.verify(key, message, tag);");
    System.out.println("  }");
    System.out.println();

    byte[] message = DEMO_MESSAGE.getBytes(StandardCharsets.UTF_8);
    try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
      byte[] tag = HmacIntegrity.sign(key, message);
      boolean ok = HmacIntegrity.verify(key, message, tag);

      System.out.println("Result:");
      System.out.println("  Algorithm: " + algorithmName(HmacIntegrity.DEFAULT_ALGORITHM));
      System.out.println("  Tag (" + tag.length + " bytes, shown as Base64):");
      System.out.println("    " + Base64.getEncoder().encodeToString(tag));
      System.out.println("  Verification result: " + ok);
    }

    ConsoleHelper.pause(scanner);
  }

  public static void tamperedMessage(Scanner scanner) {
    ConsoleHelper.header("Scenario: Verify a tampered message");

    System.out.println("What we're doing:");
    System.out.println("  Sign a payment instruction, change the amount, then verify the");
    System.out.println("  changed message against the original tag.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  byte[] tag = HmacIntegrity.sign(key, original);");
    System.out.println("  boolean ok = HmacIntegrity.verify(key, tampered, tag);");
    System.out.println();

    byte[] original = DEMO_MESSAGE.getBytes(StandardCharsets.UTF_8);
    byte[] tampered = TAMPERED_MESSAGE.getBytes(StandardCharsets.UTF_8);
    try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
      byte[] tag = HmacIntegrity.sign(key, original);
      boolean ok = HmacIntegrity.verify(key, tampered, tag);

      System.out.println("Result:");
      System.out.println("  Original: " + DEMO_MESSAGE);
      System.out.println("  Tampered: " + TAMPERED_MESSAGE);
      System.out.println("  Verification result: " + ok);
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  The tag covers every byte of the message, so changing a single");
    System.out.println("  character makes verification fail. A mismatch returns false");
    System.out.println("  rather than throwing, just like a wrong password.");

    ConsoleHelper.pause(scanner);
  }

  public static void wrongKey(Scanner scanner) {
    ConsoleHelper.header("Scenario: Verify with the wrong key");

    System.out.println("What we're doing:");
    System.out.println("  Sign a message with one key, then verify it with a different key.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  byte[] tag = HmacIntegrity.sign(key, message);");
    System.out.println("  boolean ok = HmacIntegrity.verify(otherKey, message, tag);");
    System.out.println();

    byte[] message = DEMO_MESSAGE.getBytes(StandardCharsets.UTF_8);
    try (HmacIntegrity.Key key = HmacIntegrity.generateKey();
        HmacIntegrity.Key otherKey = HmacIntegrity.generateKey()) {
      byte[] tag = HmacIntegrity.sign(key, message);
      boolean ok = HmacIntegrity.verify(otherKey, message, tag);

      System.out.println("Result:");
      System.out.println("  Verification result: " + ok);
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  Only a holder of the secret key can produce a valid tag. This is");
    System.out.println("  what separates HMAC from a plain hash like SHA-256, which anyone");
    System.out.println("  can recompute after altering the data.");

    ConsoleHelper.pause(scanner);
  }

  public static void shortKey(Scanner scanner) {
    ConsoleHelper.header("Scenario: Reject a short key");

    System.out.println("What we're doing:");
    System.out.println(
        "  Attempt to create an HMAC key from only " + SHORT_KEY_LENGTH + " bytes of material.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  byte[] shortMaterial = new byte[" + SHORT_KEY_LENGTH + "];");
    System.out.println("  HmacIntegrity.Key.of(shortMaterial);");
    System.out.println();

    byte[] shortMaterial = new byte[SHORT_KEY_LENGTH];

    System.out.println("Result:");
    try {
      HmacIntegrity.Key.of(shortMaterial).close();
      System.out.println("  Key creation returned without throwing (unexpected!)");
    } catch (IllegalArgumentException e) {
      System.out.println("  " + e.getClass().getSimpleName() + ": " + e.getMessage());
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println(
        "  Keys shorter than "
            + HmacIntegrity.Key.KEY_LENGTH_MIN
            + " bytes are rejected before any crypto work runs.");
    System.out.println("  HmacIntegrity.generateKey() always produces a key of a safe size,");
    System.out.println("  so most callers never need to handle raw key material at all.");

    ConsoleHelper.pause(scanner);
  }

  public static void truncatedTag(Scanner scanner) {
    ConsoleHelper.header("Scenario: Reject a truncated tag");

    System.out.println("What we're doing:");
    System.out.println(
        "  Sign a message, keep only the first " + TRUNCATED_TAG_LENGTH + " bytes of the tag,");
    System.out.println("  then verify the message with the shortened tag.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  byte[] tag = HmacIntegrity.sign(key, message);");
    System.out.println("  byte[] truncated = Arrays.copyOf(tag, " + TRUNCATED_TAG_LENGTH + ");");
    System.out.println("  HmacIntegrity.verify(key, message, truncated);");
    System.out.println();

    byte[] message = DEMO_MESSAGE.getBytes(StandardCharsets.UTF_8);
    try (HmacIntegrity.Key key = HmacIntegrity.generateKey()) {
      byte[] tag = HmacIntegrity.sign(key, message);
      byte[] truncated = Arrays.copyOf(tag, TRUNCATED_TAG_LENGTH);

      System.out.println("Result:");
      try {
        HmacIntegrity.verify(key, message, truncated);
        System.out.println("  Verification returned without throwing (unexpected!)");
      } catch (IllegalArgumentException e) {
        System.out.println("  " + e.getClass().getSimpleName() + ": " + e.getMessage());
      }
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  A verifier that only compares the bytes it is given would accept a");
    System.out.println("  forged 1-byte tag one time in 256. The library accepts only a tag of");
    System.out.println("  the exact length the algorithm produces, and throws because a");
    System.out.println("  wrong-length tag is malformed input, not merely a mismatch.");

    ConsoleHelper.pause(scanner);
  }

  public static void closedKey(Scanner scanner) {
    ConsoleHelper.header("Scenario: Use a closed key");

    System.out.println("What we're doing:");
    System.out.println("  Close a key, then try to sign a message with it.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  HmacIntegrity.Key key = HmacIntegrity.generateKey();");
    System.out.println("  key.close();");
    System.out.println("  HmacIntegrity.sign(key, message);");
    System.out.println();

    byte[] message = DEMO_MESSAGE.getBytes(StandardCharsets.UTF_8);
    HmacIntegrity.Key key = HmacIntegrity.generateKey();
    key.close();

    System.out.println("Result:");
    try {
      HmacIntegrity.sign(key, message);
      System.out.println("  Signing returned without throwing (unexpected!)");
    } catch (IntegrityException e) {
      System.out.println("  " + e.getClass().getSimpleName() + ": " + e.getMessage());
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  close() overwrites the key material with zeros, and any later use");
    System.out.println("  throws instead of quietly signing with a blank key. Open keys in a");
    System.out.println("  try-with-resources block so they are closed automatically.");

    ConsoleHelper.pause(scanner);
  }

  static String algorithmName(HmacIntegrity.Algorithm algorithm) {
    return "HMAC-" + algorithm.name();
  }
}
