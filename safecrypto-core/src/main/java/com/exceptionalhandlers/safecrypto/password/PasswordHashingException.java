package com.exceptionalhandlers.safecrypto.password;

/**
 * Thrown when a cryptographic operation in {@link PasswordHasher} fails due to a JVM configuration
 * problem, such as the required algorithm not being available.
 *
 * <p>This is an unchecked exception because callers cannot reasonably recover from it at runtime.
 */
public final class PasswordHashingException extends RuntimeException {

  /**
   * @param message a description of the failure
   * @param cause the underlying exception
   */
  public PasswordHashingException(String message, Throwable cause) {
    super(message, cause);
  }
}
