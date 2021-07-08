package org.wfanet.consentsignaling.crypto

import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

/**
 * TODO TinkHybridCryptor will be an implementation of Crypto that uses Google Tink as its crypto engine
 */
class TinkHybridCryptor : HybridCryptor {
  override fun encrypt(publicKey: EncryptionPublicKey, data: ByteArray): ByteArray {
    TODO("Not yet implemented")
  }

  override fun decrypt(privateKeyHandle: PrivateKeyHandle, encryptedData: ByteArray): ByteArray {
    TODO("Not yet implemented")
  }
}
