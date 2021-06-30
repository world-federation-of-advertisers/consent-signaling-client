package org.wfanet.consentsignaling.crypto.signage

import org.wfanet.consentsignaling.crypto.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate

/**
 * NoSignage is an implementation of Signage that actually does nothing.  This should only be used
 * for bringup, unit testing, or debugging.  Do not use in Production.
 */
class NoSignage : Signage {
  override fun sign(
    certificate: Certificate,
    privateKeyHandle: PrivateKeyHandle,
    data: ByteArray
  ): ByteArray {
    return "".toByteArray()
  }

  override fun verify(certificate: Certificate, signature: ByteArray, data: ByteArray): Boolean {
    return true
  }
}
