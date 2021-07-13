package org.wfanet.consentsignaling.crypto.signage

import com.google.protobuf.ByteString
import java.util.Arrays
import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate

/**
 * FakeSigner is an implementation of Signer that returns the signature as the reverse of the
 * original data. This should only be used for bring-up, unit testing, or debugging. Do not use in
 * Production.
 */
class FakeSigner(val signatureLength: Int = 10) : Signer {
  override fun sign(
    certificate: Certificate,
    privateKeyHandle: PrivateKeyHandle,
    data: ByteString
  ): ByteArray {
    return data.toByteArray().reversedArray().take(signatureLength).toByteArray()
  }

  override fun verify(certificate: Certificate, signature: ByteArray, data: ByteString): Boolean {
    return Arrays.equals(
      data.toByteArray().reversedArray().take(signatureLength).toByteArray(),
      signature
    )
  }
}
