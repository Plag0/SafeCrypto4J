package com.exceptionalhandlers.safecrypto.demo;

import java.util.Scanner;

/** Console output helpers for the demo CLI. */
public final class ConsoleHelper {

  private static final int MIN_RULE_LENGTH = 40;

  private ConsoleHelper() {}

  /** Prints a header with an underline and overline. */
  public static void header(String title) {
    String rule = "=".repeat(Math.max(title.length(), MIN_RULE_LENGTH));
    System.out.println();
    System.out.println(rule);
    System.out.println(title);
    System.out.println(rule);
    System.out.println();
  }

  /** Prints a section header with an underline. */
  public static void subheader(String title) {
    String rule = "-".repeat(Math.max(title.length(), MIN_RULE_LENGTH));
    System.out.println();
    System.out.println(rule);
    System.out.println(title);
  }

  /** Blocks until the user presses enter. */
  public static void pause(Scanner scanner) {
    System.out.println();
    System.out.print("Press enter to continue...");
    scanner.nextLine();
  }
}
