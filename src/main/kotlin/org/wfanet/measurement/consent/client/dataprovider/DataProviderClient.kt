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

package org.wfanet.measurement.consent.client.dataprovider

import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.PrivateKeyHandle
import org.wfanet.measurement.common.crypto.hashSha256
import org.wfanet.measurement.common.crypto.verifySignature

/** Computes the "requisition fingerprint" for [requisition]. */
fun computeRequisitionFingerprint(requisition: Requisition): ByteString {
  return hashSha256(
    requisition.measurementSpec.data.concat(hashSha256(requisition.encryptedRequisitionSpec))
  )
}

/**
 * Verify the MeasurementSpec from the MeasurementConsumer
 * 1. Verifies the [measurementSpec] against the [measurementSpecSignature]
 * 2. TODO: Check for replay attacks for [measurementSpecSignature]
 * 3. TODO: Verify certificate chain for [measurementConsumerCertificate]
 */
fun verifyMeasurementSpec(
  measurementSpecSignature: ByteString,
  measurementSpec: MeasurementSpec,
  measurementConsumerCertificate: X509Certificate
): Boolean {
  return measurementConsumerCertificate.verifySignature(
    measurementSpec.toByteString(),
    measurementSpecSignature
  )
}

/**
 * Decrypts a signed [RequisitionSpec].
 *
 * @param encryptedSignedDataRequisitionSpec an encrypted [SignedData] containing a
 * [RequisitionSpec].
 * @param dataProviderPrivateKey the DataProvider's encryption private key.
 */
fun decryptRequisitionSpec(
  encryptedSignedDataRequisitionSpec: ByteString,
  dataProviderPrivateKey: PrivateKeyHandle
): SignedData {
  return SignedData.parseFrom(
    dataProviderPrivateKey.hybridDecrypt(encryptedSignedDataRequisitionSpec)
  )
}

/**
 * Verifies [requisitionSpec] from the MeasurementConsumer.
 *
 * The steps are:
 * 1. TODO: Check for replay attacks
 * 2. TODO: Verify certificate chain for [measurementConsumerCertificate]
 * 3. Verify the [requisitionSpecSignature]
 * 4. Compare the measurement encryption key to the one in [measurementSpec]
 * 5. Compute the hash of the nonce and verify that the list in [measurementSpec] contains it
 */
fun verifyRequisitionSpec(
  requisitionSpecSignature: ByteString,
  requisitionSpec: RequisitionSpec,
  measurementSpec: MeasurementSpec,
  measurementConsumerCertificate: X509Certificate
): Boolean {
  return measurementConsumerCertificate.verifySignature(
    requisitionSpec.toByteString(),
    requisitionSpecSignature
  ) &&
    requisitionSpec.measurementPublicKey.equals(measurementSpec.measurementPublicKey) &&
    measurementSpec.nonceHashesList.contains(hashSha256(requisitionSpec.nonce))
}

/**
 * Verify the [elGamalPublicKeySignature] from another duchy.
 * 1. Verifies the [elGamalPublicKey] against the [elGamalPublicKeySignature]
 * 2. TODO: Check for replay attacks for [elGamalPublicKeySignature]
 * 3. TODO: Verify certificate chain for [duchyCertificate]
 */
fun verifyElGamalPublicKey(
  elGamalPublicKeySignature: ByteString,
  elGamalPublicKey: ElGamalPublicKey,
  duchyCertificate: X509Certificate
): Boolean {
  return duchyCertificate.verifySignature(
    elGamalPublicKey.toByteString(),
    elGamalPublicKeySignature
  )
}
