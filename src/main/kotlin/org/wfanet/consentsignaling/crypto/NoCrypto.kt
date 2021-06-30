package org.wfanet.consentsignaling.crypto

import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

/**
 * NoCrypto is an implementation of Crypto that actually does no crypto.  This should only be used
 * for bringup, unit testing, or debugging.  Do not use in Production.
 */
class NoCrypto : Crypto {
  override fun encrypt(publicKey: EncryptionPublicKey, data: ByteArray): ByteArray {
    return data
  }

  override fun decrypt(privateKeyHandle: PrivateKeyHandle, encryptedData: ByteArray): ByteArray {
    return encryptedData
  }
}
