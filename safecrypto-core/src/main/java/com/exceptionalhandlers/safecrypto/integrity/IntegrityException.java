package com.exceptionalhandlers.safecrypto.integrity;

import com.exceptionalhandlers.safecrypto.SafeCryptoException;

/**
 * Thrown when an operation in {@link HmacIntegrity} fails because a key has been closed, or because
 * of a JVM configuration problem such as the required algorithm not being available.
 *
 * <p>This is an unchecked exception because callers cannot reasonably recover from it at runtime.
 */
public final class IntegrityException extends SafeCryptoException {

  /**
   * @param message a description of the failure
   * @param cause the underlying exception, or {@code null} if there is none
   */
  public IntegrityException(String message, Throwable cause) {
    super(message, cause);
  }
}
