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

package org.wfanet.measurement.consent.client.measurementconsumer

import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.HybridCipherSuite
import org.wfanet.measurement.api.v2alpha.Measurement.Result as MeasurementResult
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.consent.crypto.getHybridCryptorForCipherSuite
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.signMessage
import org.wfanet.measurement.consent.crypto.verifySignature

/**
 * Signs [requisitionSpec] into a [SignedData] ProtoBuf. The [measurementConsumerX509] is required
 * to determine the algorithm type of the signature
 */
suspend fun signRequisitionSpec(
    requisitionSpec: RequisitionSpec,
    measurementConsumerPrivateKeyHandle: PrivateKeyHandle,
    measurementConsumerX509: ByteString
): SignedData {
  return signMessage<RequisitionSpec>(
      message = requisitionSpec,
      privateKeyHandle = measurementConsumerPrivateKeyHandle,
      certificate = readCertificate(measurementConsumerX509))
}

/**
 * Encrypts the [SignedData] of the requisitionSpec using the specified [HybridCryptor] specified by
 * the [HybridEncryptionMapper].
 */
suspend fun encryptRequisitionSpec(
    signedRequisitionSpec: SignedData,
    measurementPublicKey: EncryptionPublicKey,
    cipherSuite: HybridCipherSuite,
    hybridEncryptionMapper: (HybridCipherSuite) -> HybridCryptor = ::getHybridCryptorForCipherSuite,
): ByteString {
  val hybridCryptor: HybridCryptor = hybridEncryptionMapper(cipherSuite)
  return hybridCryptor.encrypt(measurementPublicKey, signedRequisitionSpec.toByteString())
}

/**
 * Signs [measurementSpec] into a [SignedData] ProtoBuf. The [measurementConsumerX509] is required
 * to determine the algorithm type of the signature
 */
suspend fun signMeasurementSpec(
    measurementSpec: MeasurementSpec,
    measurementConsumerPrivateKeyHandle: PrivateKeyHandle,
    measurementConsumerX509: ByteString
): SignedData {
  return signMessage<MeasurementSpec>(
      message = measurementSpec,
      privateKeyHandle = measurementConsumerPrivateKeyHandle,
      certificate = readCertificate(measurementConsumerX509))
}

/** Signs the measurementConsumer's encryptionPublicKey. */
suspend fun signEncryptionPublicKey(
    encryptionPublicKey: EncryptionPublicKey,
    privateKeyHandle: PrivateKeyHandle,
    measurementConsumerX509: ByteString
): SignedData {
  return signMessage<EncryptionPublicKey>(
      message = encryptionPublicKey,
      privateKeyHandle = privateKeyHandle,
      certificate = readCertificate(measurementConsumerX509))
}

/**
 * Verify the Result from the Aggregator
 * 1. Verifies the [measurementResult] against the [resultSignature]
 * 2. TODO: Check for replay attacks for [resultSignature]
 * 3. TODO: Verify certificate chain for [aggregatorCertificate]
 */
suspend fun verifyResult(
    resultSignature: ByteString,
    measurementResult: MeasurementResult,
    aggregatorCertificate: X509Certificate
): Boolean {
  return aggregatorCertificate.verifySignature(measurementResult.toByteString(), resultSignature)
}
