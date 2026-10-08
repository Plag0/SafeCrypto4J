package com.exceptionalhandlers.safecrypto.integrity;

/**
 * Thrown when an operation in {@link HmacIntegrity} fails due to invalid integrity state, or a JVM
 * configuration problem, such as the required algorithm not being available.
 *
 * <p>This is an unchecked exception because callers cannot reasonably recover from it at runtime.
 */
public final class IntegrityException extends RuntimeException {

  /**
   * @param message a description of the failure
   * @param cause the underlying exception (if one exists)
   */
  public IntegrityException(String message, Throwable cause) {
    super(message, cause);
  }
}
