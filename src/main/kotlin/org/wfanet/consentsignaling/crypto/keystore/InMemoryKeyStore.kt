package org.wfanet.consentsignaling.crypto.keystore

import org.wfanet.consentsignaling.crypto.PrivateKeyHandle

/**
 * A simple "In-Memory" implementation of KeyStore using a HashMap
 *
 * This is for bringup and unit testing only. This is not secure and should not be used in production.
 */
class InMemoryKeyStore : KeyStore() {
  private val keyStoreMap = HashMap<String, ByteArray>()

  override fun storePrivateKeyDER(id: String, privateKeyBytes: ByteArray): PrivateKeyHandle {
    keyStoreMap[id] = privateKeyBytes
    return PrivateKeyHandle(id, this)
  }

  override fun getPrivateKeyHandle(id: String): PrivateKeyHandle {
    keyStoreMap[id]?.let {
      return PrivateKeyHandle(id, this)
    }
    throw KeyNotFoundException(id)
  }

  override fun readPrivateKey(privateKeyHandle: PrivateKeyHandle): ByteArray {
    keyStoreMap[privateKeyHandle.id]?.let {
      return it
    }
    throw KeyNotFoundException(privateKeyHandle.id)
  }
}
