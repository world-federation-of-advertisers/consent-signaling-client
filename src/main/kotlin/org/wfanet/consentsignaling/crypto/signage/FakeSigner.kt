package org.wfanet.consentsignaling.crypto.signage

import com.google.protobuf.ByteString
import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate

/**
 * FakeSigner is an implementation of Signer that actually does nothing. This should only be used
 * for bring-up, unit testing, or debugging. Do not use in Production.
 */
class FakeSigner : Signer {
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
