// Copyright 2021 The Cross-Media Measurement Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.wfanet.consentsignaling.crypto.signage

import com.google.protobuf.ByteString
import java.util.Arrays
import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate

/**
 * [FakeSigner] is an implementation of [Signer] that returns the [signature] as the reverse of the
 * original data. This should only be used for bring-up, unit testing, or debugging. Do not use in
 * production.
 */
class FakeSigner(val signatureLength: Int = 10) : Signer {
  override fun sign(
    certificate: Certificate,
    privateKeyHandle: PrivateKeyHandle,
    data: ByteString
  ): ByteString {
    return ByteString.copyFrom(
      data.toByteArray().reversedArray().take(signatureLength).toByteArray()
    )
  }

  override fun verify(certificate: Certificate, signature: ByteString, data: ByteString): Boolean {
    return Arrays.equals(
      data.toByteArray().reversedArray().take(signatureLength).toByteArray(),
      signature.toByteArray()
    )
  }
}
