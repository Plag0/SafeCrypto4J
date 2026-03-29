package com.exceptionalhandlers.safecrypto.encryption;

/** Thrown when AES encryption or decryption fails. */
public class EncryptionException extends RuntimeException {

  public EncryptionException(String message, Throwable cause) {
    super(message, cause);
  }
}
