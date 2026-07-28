package com.exceptionalhandlers.safecrypto.demo;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * A reusable text menu. The menu loops until the user selects the exit option, at which point
 * control returns to whoever called {@link #show()}.
 */
public final class Menu {

  private final String title;
  private final String exitLabel;
  private final Scanner scanner;
  private final List<MenuItem> items = new ArrayList<>();

  /**
   * @param title shown as the menu's header
   * @param exitLabel label for option {@code 0}
   * @param scanner shared {@link Scanner} used to read input
   */
  public Menu(String title, String exitLabel, Scanner scanner) {
    this.title = title;
    this.exitLabel = exitLabel;
    this.scanner = scanner;
  }

  /** Adds a numbered option to the menu. Returns this for chaining. */
  public Menu add(String label, Runnable action) {
    items.add(new MenuItem(label, action));
    return this;
  }

  /** Displays the menu and processes selections until the user exits. */
  public void show() {
    while (true) {
      ConsoleHelper.header(title);
      for (int i = 0; i < items.size(); i++) {
        System.out.println((i + 1) + ". " + items.get(i).label());
      }
      System.out.println("0. " + exitLabel);
      System.out.println();
      System.out.print("> ");

      String input = scanner.nextLine().trim();
      if (input.equals("0")) {
        return;
      }

      MenuItem chosen = parseChoice(input);
      if (chosen == null) {
        System.out.println();
        System.out.println("Unrecognised option. Try again.");
      } else {
        chosen.action().run();
      }
    }
  }

  private MenuItem parseChoice(String input) {
    try {
      int index = Integer.parseInt(input) - 1;
      if (index >= 0 && index < items.size()) {
        return items.get(index);
      }
    } catch (NumberFormatException ignored) {
      // Fall through to return null.
    }
    return null;
  }

  private record MenuItem(String label, Runnable action) {}
}
