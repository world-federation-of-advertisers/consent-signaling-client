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

package org.wfanet.measurement.consent.client.kingdom

import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.validate
import org.wfanet.measurement.consent.client.common.verifySignedData

/**
 * Verify the MeasurementSpec from the MeasurementConsumer.
 *
 * 1. Validates the certificate path from [measurementConsumerCertificate] to [trustedIssuer]
 * 2. Verifies the [signature][SignedData.getSignature] of [signedMeasurementSpec] against its
 * [data][SignedData.getData]
 * 3. TODO: Check for replay attacks for [signedMeasurementSpec]'s signature
 *
 * @throws CertPathValidatorException if [measurementConsumerCertificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
@Throws(CertPathValidatorException::class, SignatureException::class)
fun verifyMeasurementSpec(
  signedMeasurementSpec: SignedData,
  measurementConsumerCertificate: X509Certificate,
  trustedIssuer: X509Certificate
) {
  measurementConsumerCertificate.run {
    validate(trustedIssuer)
    verifySignedData(signedMeasurementSpec)
  }
}
