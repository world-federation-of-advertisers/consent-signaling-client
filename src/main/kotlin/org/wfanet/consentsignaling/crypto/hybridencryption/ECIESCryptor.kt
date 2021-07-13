package org.wfanet.consentsignaling.crypto.hybridencryption

import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

/**
 * TODO ECIESCryptor will be an implementation of Crypto that uses Google Tink as its crypto engine
 */
class ECIESCryptor : HybridCryptor {
  override fun encrypt(recipientPublicKey: EncryptionPublicKey, data: ByteArray): ByteArray {
    TODO("Not yet implemented")
  }

  override fun decrypt(privateKeyHandle: PrivateKeyHandle, encryptedData: ByteArray): ByteArray {
    TODO("Not yet implemented")
  }
}
