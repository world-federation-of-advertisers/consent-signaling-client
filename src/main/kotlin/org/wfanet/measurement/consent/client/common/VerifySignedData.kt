/*
 * Copyright 2021 The Cross-Media Measurement Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wfanet.measurement.consent.client.common

import java.security.SignatureException
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.verifySignature

/**
 * Verifies the [signature][SignedData.getSignature] against the [data][SignedData.getData].
 *
 * @throws SignatureException if the signature is invalid
 */
@Throws(SignatureException::class)
fun X509Certificate.verifySignedData(signedData: SignedData) {
  if (!verifySignature(signedData.data, signedData.signature)) {
    throw SignatureException("Signature is invalid")
  }
}
