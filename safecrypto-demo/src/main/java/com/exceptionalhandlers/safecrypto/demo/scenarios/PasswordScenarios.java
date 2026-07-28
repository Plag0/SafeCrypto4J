package com.exceptionalhandlers.safecrypto.demo.scenarios;

import com.exceptionalhandlers.safecrypto.demo.ConsoleHelper;
import com.exceptionalhandlers.safecrypto.password.PasswordHasher;
import java.util.Scanner;

/** End-to-end demonstrations of {@link PasswordHasher}. */
public final class PasswordScenarios {

  private static final String DEMO_PASSWORD = "demo-password-123";
  private static final String WRONG_PASSWORD = "not-the-right-one";

  private PasswordScenarios() {}

  public static void hashAndVerify(Scanner scanner) {
    ConsoleHelper.header("Scenario: Hash and verify a password");

    System.out.println("What we're doing:");
    System.out.println("  Hash a password, then verify the same password against the");
    System.out.println("  stored hash.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  char[] password = \"" + DEMO_PASSWORD + "\".toCharArray();");
    System.out.println("  String stored = PasswordHasher.hashPassword(password);");
    System.out.println("  boolean ok = PasswordHasher.verifyPassword(password, stored);");
    System.out.println();

    char[] password = DEMO_PASSWORD.toCharArray();
    String stored = PasswordHasher.hashPassword(password);
    boolean ok = PasswordHasher.verifyPassword(password, stored);

    System.out.println("Result:");
    System.out.println("  Stored hash: " + stored);
    System.out.println("  Verification result: " + ok);

    ConsoleHelper.pause(scanner);
  }

  public static void wrongPassword(Scanner scanner) {
    ConsoleHelper.header("Scenario: Verify with the wrong password");

    System.out.println("What we're doing:");
    System.out.println("  Hash one password, then attempt to verify a different password");
    System.out.println("  against the stored hash.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  String stored = PasswordHasher.hashPassword(correctPassword);");
    System.out.println("  boolean ok = PasswordHasher.verifyPassword(wrongPassword, stored);");
    System.out.println();

    char[] correct = DEMO_PASSWORD.toCharArray();
    char[] wrong = WRONG_PASSWORD.toCharArray();
    String stored = PasswordHasher.hashPassword(correct);
    boolean ok = PasswordHasher.verifyPassword(wrong, stored);

    System.out.println("Result:");
    System.out.println("  Verification result: " + ok);
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  A wrong password returns false rather than throwing an exception.");
    System.out.println("  Exceptions are reserved for genuinely abnormal conditions such as");
    System.out.println("  a corrupt stored hash, so callers can distinguish the two cases.");

    ConsoleHelper.pause(scanner);
  }

  public static void tamperedHash(Scanner scanner) {
    ConsoleHelper.header("Scenario: Tampered hash rejection");

    System.out.println("What we're doing:");
    System.out.println("  Take a valid stored hash, lower its iteration count to 1, and");
    System.out.println("  attempt verification.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  String stored = PasswordHasher.hashPassword(password);");
    System.out.println("  String[] parts = stored.split(\":\", 3);");
    System.out.println("  String tampered = \"1:\" + parts[1] + \":\" + parts[2];");
    System.out.println("  PasswordHasher.verifyPassword(password, tampered);");
    System.out.println();

    char[] password = DEMO_PASSWORD.toCharArray();
    String stored = PasswordHasher.hashPassword(password);
    String[] parts = stored.split(":", 3);
    String tampered = "1:" + parts[1] + ":" + parts[2];

    System.out.println("Result:");
    try {
      PasswordHasher.verifyPassword(password, tampered);
      System.out.println("  Verification returned without throwing (unexpected!)");
    } catch (IllegalArgumentException e) {
      System.out.println("  " + e.getClass().getSimpleName() + ": " + e.getMessage());
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  The library enforces a minimum work factor at verification time,");
    System.out.println("  so an attacker who can write to the hash store cannot trivially");
    System.out.println("  weaken protection.");

    ConsoleHelper.pause(scanner);
  }

  public static void malformedInput(Scanner scanner) {
    ConsoleHelper.header("Scenario: Verify with malformed input");

    String malformed = "this-is-not-a-real-hash";

    System.out.println("What we're doing:");
    System.out.println("  Attempt to verify against a string that is not a valid stored hash.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  String malformed = \"" + malformed + "\";");
    System.out.println("  PasswordHasher.verifyPassword(password, malformed);");
    System.out.println();

    char[] password = DEMO_PASSWORD.toCharArray();

    System.out.println("Result:");
    try {
      PasswordHasher.verifyPassword(password, malformed);
      System.out.println("  Verification returned without throwing (unexpected!)");
    } catch (IllegalArgumentException e) {
      System.out.println("  " + e.getClass().getSimpleName() + ": " + e.getMessage());
    }
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  Format errors throw with a clear message rather than returning");
    System.out.println("  false, so callers can tell a corrupt stored value apart from a");
    System.out.println("  wrong password.");

    ConsoleHelper.pause(scanner);
  }

  public static void saltUniqueness(Scanner scanner) {
    ConsoleHelper.header("Scenario: Salt uniqueness");

    System.out.println("What we're doing:");
    System.out.println("  Hash the same password twice and compare the two stored hashes.");
    System.out.println();
    System.out.println("Code:");
    System.out.println("  String first = PasswordHasher.hashPassword(password);");
    System.out.println("  String second = PasswordHasher.hashPassword(password);");
    System.out.println();

    char[] password = DEMO_PASSWORD.toCharArray();
    String first = PasswordHasher.hashPassword(password);
    String second = PasswordHasher.hashPassword(password);

    System.out.println("Result:");
    System.out.println("  First:  " + first);
    System.out.println("  Second: " + second);
    System.out.println("  Equal:  " + first.equals(second));
    System.out.println();
    System.out.println("Why this matters:");
    System.out.println("  Each hash uses a fresh random salt, so identical passwords produce");
    System.out.println("  different stored values. This defeats rainbow table attacks and");
    System.out.println("  prevents an observer from telling whether two users share a");
    System.out.println("  password.");

    ConsoleHelper.pause(scanner);
  }
}
