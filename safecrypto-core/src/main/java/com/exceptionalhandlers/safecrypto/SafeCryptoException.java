package com.exceptionalhandlers.safecrypto;

/**
 * Parent of the exceptions SafeCrypto4J throws when a cryptographic operation fails. Invalid
 * arguments are reported with {@link IllegalArgumentException} instead.
 */
public abstract class SafeCryptoException extends RuntimeException {

  /**
   * @param message a description of the failure; must not contain secret material
   * @param cause the underlying exception, or {@code null} if there is none
   */
  protected SafeCryptoException(String message, Throwable cause) {
    super(message, cause);
  }
}
