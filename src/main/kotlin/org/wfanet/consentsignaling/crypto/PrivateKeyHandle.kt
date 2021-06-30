package org.wfanet.consentsignaling.crypto

import com.google.crypto.tink.KeysetHandle
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import org.wfanet.consentsignaling.crypto.keystore.KeyStore

/**
 * PrivateKey Handles can only be created inside of this 'crypto' module.  The allow a client
 * to have a handle to a private key, yet are not able to gain access to the contents of the
 * private key.  Only the 'crypto' module can read the bytes of the private key.
 *
 * Conveience methods of toTinkKeysetHandle and toJavaPrivateKey are included and used by various
 * parts of the 'crypto' library
 */
class PrivateKeyHandle internal constructor(
  val id: String,
  private val keyStore: KeyStore
) {

  /**
   * Converts the PrivateKeyHandle into a usable Tink KeysetHandle object (used by TinkCrypto)
   *
   * 'crypto' module internal use only
   */
  internal fun toTinkKeysetHandle(): KeysetHandle {
    TODO("Not yet implemented")
  }

  /**
   * Converts a PrivateKeyHandle into a Java Security Private Key object
   *
   * 'crypto' module internal use only
   */
  internal fun toJavaPrivateKey(): PrivateKey {
    return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(toByteArray()))
  }

  /**
   * Returns the private key in a byte array (generic)
   *
   * 'crypto' module internal use only
   */
  internal fun toByteArray(): ByteArray {
    return keyStore.readPrivateKey(this)
  }
}
