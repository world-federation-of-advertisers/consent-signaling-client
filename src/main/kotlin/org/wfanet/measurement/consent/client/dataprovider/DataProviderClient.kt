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
import kotlin.reflect.KFunction0
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.ExchangeStep
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
import org.wfanet.measurement.consent.crypto.verifyExchangeStepSignatures as verifyExchangeStepSignaturesCommon
import org.wfanet.measurement.consent.crypto.verifySignature

data class RequisitionSpecAndFingerprint(
  /** Decrypted Signed RequisitionSpec */
  val signedRequisitionSpec: SignedData,
  /** Generated Requisition Fingerprint */
  val requisitionFingerprint: ByteString,
)
/**
 * Decrypts the RequisitionSpec from the [requisition] and generates the RequisitionFingerprint
 *
 * A RequisitionFingerprint is the concatenation of a. The SHA-256 hash of the encrypted
 * RequisitionSpec b. The ParticipantListHash c. The serialized MeasurementSpec
 *
 * We assume the signed [requisition].measurementSpec was verified when the requisition was
 * initially received by the data provider.
 *
 * @return a [RequisitionSpecAndFingerprint] containing the decrypted RequisitionSpec and generated
 * RequisitionFingerprint
 */
suspend fun decryptRequisitionSpecAndGenerateRequisitionFingerprint(
  requisition: Requisition,
  decryptionPrivateKeyHandle: PrivateKeyHandle,
  hybridEncryptionMapper: KFunction0<HybridCryptor> = ::getHybridCryptorForCipherSuite,
): RequisitionSpecAndFingerprint {
  val decryptedRequisitionSpec =
    decryptRequisitionSpec(
      requisition.encryptedRequisitionSpec,
      decryptionPrivateKeyHandle,
      hybridEncryptionMapper
    )
  // There is no salt when hashing the encrypted requisition spec
  val hashedEncryptedRequisitionSpec: ByteString = hashSha256(requisition.encryptedRequisitionSpec)
  val requisitionSpec = RequisitionSpec.parseFrom(decryptedRequisitionSpec.data)
  val requisitionFingerprint =
    hashedEncryptedRequisitionSpec
      .concat(requireNotNull(requisitionSpec.dataProviderListHash))
      .concat(requireNotNull(requisition.measurementSpec.data))
  return RequisitionSpecAndFingerprint(decryptedRequisitionSpec, requisitionFingerprint)
}

/** Signs the RequisitionFingerprint resulting in the participationSignature */
suspend fun signRequisitionFingerprint(
  requisitionFingerprint: ByteString,
  consentSignalingPrivateKeyHandle: PrivateKeyHandle,
  consentSignalingCertificate: X509Certificate,
): SignedData {
  val dataProviderPrivateKey: PrivateKey =
    checkNotNull(consentSignalingPrivateKeyHandle.toJavaPrivateKey(consentSignalingCertificate))
  val participationSignature =
    dataProviderPrivateKey.sign(
      certificate = consentSignalingCertificate,
      data = requisitionFingerprint
    )
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
  hybridEncryptionMapper: KFunction0<HybridCryptor> = ::getHybridCryptorForCipherSuite,
): SignedData {
  val hybridCryptor: HybridCryptor = hybridEncryptionMapper()
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

/**
 * Verifies that the [signedExchangeWorkflow] was signed by both the entities represented by
 * [modelProviderCertificate] and [dataProviderCertificate]
 */
fun verifyExchangeStepSignatures(
  signedExchangeWorkflow: ExchangeStep.SignedExchangeWorkflow,
  modelProviderCertificate: X509Certificate,
  dataProviderCertificate: X509Certificate,
): Boolean =
  verifyExchangeStepSignaturesCommon(
    signedExchangeWorkflow,
    modelProviderCertificate,
    dataProviderCertificate,
  )
