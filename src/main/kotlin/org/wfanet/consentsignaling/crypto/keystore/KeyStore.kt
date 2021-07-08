package org.wfanet.consentsignaling.crypto.keystore

import com.google.protobuf.ByteString
import org.wfanet.consentsignaling.crypto.PrivateKeyHandle

/**
 * KeyStore is an abstract class for storing private keys in different implementation of KMS
 *
 * Clients of this class can store PrivateKeys (currently in DER format) and can retrieve a
 * PrivateKeyHandle of the stored key, however the client will not be enable to read the actual
 * key contents stored in KMS.  Only this 'crypto' module will have access to the actual private
 * key contents (currently used by signage and crypto classes)
 */
abstract class KeyStore {
  class KeyNotFoundException(id: String) : Exception("Private key $id was not found")

  /**
   * Store the a private key in KeyStorage and returns a PrivateKeyHandle
   */
  abstract fun storePrivateKeyDER(id: String, privateKeyBytes: ByteString): PrivateKeyHandle

  /**
   * Retrieves a PrivateKeyHandle of an existing key in KeyStore
   */
  abstract fun getPrivateKeyHandle(id: String): PrivateKeyHandle

  /**
   * Reads the contents of a private key stored in KeyStore.  This can only be access by this
   * 'crypto' module
   */
  internal abstract fun readPrivateKey(privateKeyHandle: PrivateKeyHandle): ByteString
}
