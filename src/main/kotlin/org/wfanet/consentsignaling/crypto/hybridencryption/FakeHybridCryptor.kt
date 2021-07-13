package org.wfanet.consentsignaling.crypto.hybridencryption

import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

/**
 * FakeHybridCryptor is an implementation of HybridCryptor that actually does no crypto. It only
 * reverses the ByteArray. This should only be used for bringup, unit testing, or debugging. Do not
 * use in Production.
 */
class FakeHybridCryptor : HybridCryptor {
  override fun encrypt(recipientPublicKey: EncryptionPublicKey, data: ByteArray): ByteArray {
    return data.reversedArray()
  }

  override fun decrypt(privateKeyHandle: PrivateKeyHandle, encryptedData: ByteArray): ByteArray {
    return encryptedData.reversedArray()
  }
}
