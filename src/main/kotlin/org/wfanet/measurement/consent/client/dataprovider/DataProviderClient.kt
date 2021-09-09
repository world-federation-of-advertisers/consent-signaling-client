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
import java.security.PrivateKey
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.ExchangeStep
import org.wfanet.measurement.api.v2alpha.HybridCipherSuite
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.consent.crypto.getHybridCryptorForCipherSuite
import org.wfanet.measurement.consent.crypto.hashSha256
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.sign
import org.wfanet.measurement.consent.crypto.signMessage
import org.wfanet.measurement.consent.crypto.verifySignature

/**
 * Creates signature verifying EDP Participation.
 * 1. EDP computes the RequisitionFingerprint, which is the concatenation of a. The SHA-256 hash of
 * the encrypted RequisitionSpec b. The ParticipantListHash c. The serialized MeasurementSpec
 * 2. Signs the RequisitionFingerprint resulting in the participationSignature
 *
 * We assume the signed [requisition].measurementSpec was verified when the requisition was
 * initially received by the data provider.
 */
suspend fun createParticipationSignature(
  hybridCryptor: HybridCryptor,
  requisition: Requisition,
  privateKeyHandle: PrivateKeyHandle,
  dataProviderCertificate: X509Certificate
): SignedData {
  val encryptedRequisitionSpec = requisition.encryptedRequisitionSpec
  val requisitionSpec =
    RequisitionSpec.parseFrom(hybridCryptor.decrypt(privateKeyHandle, encryptedRequisitionSpec))
  // There is no salt when hashing the encrypted requisition spec
  val hashedEncryptedRequisitionSpec: ByteString = hashSha256(encryptedRequisitionSpec)
  val requisitionFingerprint =
    hashedEncryptedRequisitionSpec
      .concat(requireNotNull(requisitionSpec.dataProviderListHash))
      .concat(requireNotNull(requisition.measurementSpec.data))
  val privateKey: PrivateKey =
    requireNotNull(privateKeyHandle.toJavaPrivateKey(dataProviderCertificate))
  val participationSignature =
    privateKey.sign(certificate = dataProviderCertificate, data = requisitionFingerprint)
  return SignedData.newBuilder()
    .apply {
      data = requisitionFingerprint
      signature = participationSignature
    }
    .build()
}

/** Signs the dataProvider's encryptionPublicKey. */
suspend fun signEncryptionPublicKey(
  encryptionPublicKey: EncryptionPublicKey,
  privateKeyHandle: PrivateKeyHandle,
  dataProviderCertificate: X509Certificate
): SignedData {
  return signMessage(
    message = encryptionPublicKey,
    privateKeyHandle = privateKeyHandle,
    certificate = dataProviderCertificate
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
 * Decrypts the [encryptedSignedDataRequisitionSpec] of the requisition spec using the specified
 * [HybridCryptor] specified by the [HybridEncryptionMapper].
 */
suspend fun decryptRequisitionSpec(
  encryptedSignedDataRequisitionSpec: ByteString,
  dataProviderPrivateKeyHandle: PrivateKeyHandle,
  cipherSuite: HybridCipherSuite,
  hybridEncryptionMapper: (HybridCipherSuite) -> HybridCryptor = ::getHybridCryptorForCipherSuite,
): SignedData {
  val hybridCryptor: HybridCryptor = hybridEncryptionMapper(cipherSuite)
  return SignedData.parseFrom(
    hybridCryptor.decrypt(dataProviderPrivateKeyHandle, encryptedSignedDataRequisitionSpec)
  )
}

/**
 * Verify the RequisitionSpec from the MeasurementConsumer
 * 1. Verifies the [requisitionSpec] against the [requisitionSpecSignature]
 * 2. TODO: Check for replay attacks for [requisitionSpecSignature]
 * 3. TODO: Verify certificate chain for [measurementConsumerCertificate]
 * 4. Verifies the measurementPublicKey in requisitionSpec matches that of the corresponding
 * measurementSpec
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
  ) && requisitionSpec.measurementPublicKey.equals(measurementSpec.measurementPublicKey)
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

/** Verifies that the [signedExchangeWorkflow] was signed by both the entities represented by
 * [modelProviderCertificate] and [dataProviderCertificate]
 */
fun verifyExchangeStepSignatures(
  signedExchangeWorkflow: ExchangeStep.SignedExchangeWorkflow,
  modelProviderCertificate: X509Certificate,
  dataProviderCertificate: X509Certificate,
): Boolean {
  val signedData = signedExchangeWorkflow.serializedExchangeWorkflow
  val hasModelProviderSignature = modelProviderCertificate.verifySignature(
    signedData, signedExchangeWorkflow.modelProviderSignature
  )
  val hasDataProviderSignature = dataProviderCertificate.verifySignature(
    signedData, signedExchangeWorkflow.dataProviderSignature
  )
  return hasModelProviderSignature && hasDataProviderSignature
}
