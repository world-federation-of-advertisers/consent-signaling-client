package org.wfanet.consentsignaling.crypto.signage

import com.google.protobuf.ByteString
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
    data: ByteString
  ): ByteArray {
    return "".toByteArray()
  }

  override fun verify(certificate: Certificate, signature: ByteString, data: ByteString): Boolean {
    return true
  }
}
