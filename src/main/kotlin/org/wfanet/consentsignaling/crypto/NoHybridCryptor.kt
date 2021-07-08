package org.wfanet.consentsignaling.crypto

import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

/**
 * NoHybridCryptor is an implementation of HybridCryptor that actually does no crypto.  This should
 * only be used for bringup, unit testing, or debugging.  Do not use in Production.
 */
class NoHybridCryptor : HybridCryptor {
  override fun encrypt(publicKey: EncryptionPublicKey, data: ByteArray): ByteArray {
    return data
  }

  override fun decrypt(privateKeyHandle: PrivateKeyHandle, encryptedData: ByteArray): ByteArray {
    return encryptedData
  }
}
