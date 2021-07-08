package org.wfanet.consentsignaling.crypto

import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

/**
 * HybridCryptor is a simple interface that be implemented to encrypt and decrypt bytes
 */
interface HybridCryptor {
  /**
   * encrypt will encrypt data using the public key stored in the EncryptionPublicKey Protobuf
   */
  fun encrypt(publicKey: EncryptionPublicKey, data: ByteArray): ByteArray

  /**
   * decrypt will decrypt data using a private key stored in KeyStore
   */
  fun decrypt(privateKeyHandle: PrivateKeyHandle, encryptedData: ByteArray): ByteArray
}
