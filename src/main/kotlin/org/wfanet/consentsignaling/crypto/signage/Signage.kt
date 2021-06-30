package org.wfanet.consentsignaling.crypto.signage

import org.wfanet.consentsignaling.crypto.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate

object SignageConstants {
  const val CERTIFICATE_TYPE = "X.509"
}

/**
 * Signage is a simple interface that be implemented to sign byte array's and verify signatures
 * of signed byte arrays
 */
interface Signage {
  class CertificateTypeNotSupported(supportedTypes: String) :
    Exception("Only $supportedTypes are supported")

  /**
   * Sign a data byte array using a PrivateKeyHandle stored in Keystore.  The certificate is used to
   * determine the signature algorithm to be used
   */
  fun sign(certificate: Certificate, privateKeyHandle: PrivateKeyHandle, data: ByteArray): ByteArray
  fun verify(certificate: Certificate, signature: ByteArray, data: ByteArray): Boolean
}
