package com.exceptionalhandlers.safecrypto.encryption;

/**
 * Thrown when a cryptographic operation in {@link AesEncryptor} fails due to a JVM configuration
 * problem or decryption/authentication failure.
 *
 * <p>This is an unchecked exception because callers cannot reasonably recover from it at runtime.
 */
public final class EncryptionException extends RuntimeException {

  /**
   * @param message a description of the failure
   * @param cause the underlying exception
   */
  public EncryptionException(String message, Throwable cause) {
    super(message, cause);
  }
}
