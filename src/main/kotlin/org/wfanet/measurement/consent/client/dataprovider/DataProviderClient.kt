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
import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.EventGroup.Metadata
import org.wfanet.measurement.api.v2alpha.Measurement.Result
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.PrivateKeyHandle
import org.wfanet.measurement.common.crypto.SigningKeyHandle
import org.wfanet.measurement.common.crypto.hashSha256
import org.wfanet.measurement.common.crypto.validate
import org.wfanet.measurement.consent.client.common.NonceMismatchException
import org.wfanet.measurement.consent.client.common.PublicKeyMismatchException
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toPublicKeyHandle
import org.wfanet.measurement.consent.client.common.verifySignedData

/** Computes the "requisition fingerprint" for [requisition]. */
fun computeRequisitionFingerprint(requisition: Requisition): ByteString {
  return hashSha256(
    requisition.measurementSpec.data.concat(hashSha256(requisition.encryptedRequisitionSpec))
  )
}

/**
 * Verify the MeasurementSpec from the MeasurementConsumer.
 * 1. Validates [measurementConsumerCertificate] against [trustedIssuer]
 * 2. Verifies the [signature][SignedData.getSignature] of [signedMeasurementSpec] against its
 *    [data][SignedData.getData]
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

/**
 * Decrypts a signed [RequisitionSpec].
 *
 * @param encryptedSignedDataRequisitionSpec an encrypted [SignedData] containing a
 *   [RequisitionSpec].
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
 * 2. Verify certificate path from [measurementConsumerCertificate] to [trustedIssuer]
 * 3. Verify the [signedRequisitionSpec] [signature][SignedData.getSignature]
 * 4. Compare the measurement encryption key to the one in [measurementSpec]
 * 5. Compute the hash of the nonce and verify that the list in [measurementSpec] contains it
 *
 * @throws CertPathValidatorException if the certificate path is invalid
 * @throws SignatureException if the signature is invalid
 * @throws NonceMismatchException if nonce hashes mismatch
 * @throws PublicKeyMismatchException if the measurement public key mismatches
 */
@Throws(
  CertPathValidatorException::class,
  SignatureException::class,
  NonceMismatchException::class,
  PublicKeyMismatchException::class
)
fun verifyRequisitionSpec(
  signedRequisitionSpec: SignedData,
  requisitionSpec: RequisitionSpec,
  measurementSpec: MeasurementSpec,
  measurementConsumerCertificate: X509Certificate,
  trustedIssuer: X509Certificate
) {
  measurementConsumerCertificate.validate(trustedIssuer)
  measurementConsumerCertificate.verifySignedData(signedRequisitionSpec)
  if (requisitionSpec.measurementPublicKey != measurementSpec.measurementPublicKey) {
    throw PublicKeyMismatchException("Measurement public key mismatch")
  }
  if (!measurementSpec.nonceHashesList.contains(hashSha256(requisitionSpec.nonce))) {
    throw NonceMismatchException("Nonce hash mismatch")
  }
}

/**
 * Verifies the [signedElGamalPublicKey] from a Duchy.
 * 1. Validates the certificate path from [duchyCertificate] to [trustedDuchyIssuer]
 * 2. Verifies the [signedElGamalPublicKey] [signature][SignedData.getSignature]
 * 3. TODO: Check for replay attacks for the signature
 *
 * @throws CertPathValidatorException if [duchyCertificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
@Throws(CertPathValidatorException::class, SignatureException::class)
fun verifyElGamalPublicKey(
  signedElGamalPublicKey: SignedData,
  duchyCertificate: X509Certificate,
  trustedDuchyIssuer: X509Certificate
) {
  duchyCertificate.run {
    validate(trustedDuchyIssuer)
    verifySignedData(signedElGamalPublicKey)
  }
}

/**
 * Signs [Result] into [SignedData]
 *
 * The [dataProviderSigningKey] determines the algorithm type of the signature.
 */
fun signResult(result: Result, dataProviderSigningKey: SigningKeyHandle): SignedData {
  return result.serializeAndSign(dataProviderSigningKey)
}

/** Encrypts a [Metadata]. */
fun encryptMetadata(
  metadata: Metadata,
  measurementConsumerPublicKey: EncryptionPublicKey
): ByteString =
  measurementConsumerPublicKey.toPublicKeyHandle().hybridEncrypt(metadata.toByteString())
