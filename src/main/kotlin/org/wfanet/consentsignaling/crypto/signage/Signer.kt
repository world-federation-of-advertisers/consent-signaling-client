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
import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate

const val CERTIFICATE_TYPE = "X.509"

/** [Signer] is a simple interface that be implemented to sign and verify data. */
interface Signer {
  class CertificateTypeNotSupported(supportedTypes: String) :
    Exception("Only $supportedTypes are supported")

  /**
   * Sign [data] using a [PrivateKeyHandle]. The [certificate] is used to determine the algorithm to
   * be used. Can return null private key is not found.
   */
  fun sign(
    certificate: Certificate,
    privateKeyHandle: PrivateKeyHandle,
    data: ByteString
  ): ByteString?

  /**
   * Verify [signature] of [data]. The [certificate] is used to determine the algorithm to be used
   * and for the public key.
   */
  fun verify(certificate: Certificate, signature: ByteString, data: ByteString): Boolean
}
