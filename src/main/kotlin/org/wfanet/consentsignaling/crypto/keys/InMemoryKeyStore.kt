package org.wfanet.consentsignaling.crypto.keys

import com.google.protobuf.ByteString

/**
 * A simple "In-Memory" implementation of KeyStore using a HashMap
 *
 * This is for bringup and unit testing only. This is not secure and should not be used in
 * production.
 */
class InMemoryKeyStore : KeyStore() {
  private val keyStoreMap = HashMap<String, ByteString>()

  override fun storePrivateKeyDER(id: String, privateKeyBytes: ByteString): PrivateKeyHandle {
    keyStoreMap[id] = privateKeyBytes
    return PrivateKeyHandle(id, this)
  }

  override fun getPrivateKeyHandle(id: String): PrivateKeyHandle {
    keyStoreMap[id]?.let {
      return PrivateKeyHandle(id, this)
    }
    throw KeyNotFoundException(id)
  }

  override fun readPrivateKey(privateKeyHandle: PrivateKeyHandle): ByteString {
    keyStoreMap[privateKeyHandle.id]?.let {
      return it
    }
    throw KeyNotFoundException(privateKeyHandle.id)
  }
}
