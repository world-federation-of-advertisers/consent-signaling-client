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
import org.wfanet.measurement.api.v2alpha.EncryptedMessage
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.EventGroup.Metadata
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.RandomSeed
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedMessage
import org.wfanet.measurement.common.crypto.Hashing
import org.wfanet.measurement.common.crypto.PrivateKeyHandle
import org.wfanet.measurement.common.crypto.SignatureAlgorithm
import org.wfanet.measurement.common.crypto.SigningKeyHandle
import org.wfanet.measurement.common.crypto.validate
import org.wfanet.measurement.common.pack
import org.wfanet.measurement.consent.client.common.NonceMismatchException
import org.wfanet.measurement.consent.client.common.PublicKeyMismatchException
import org.wfanet.measurement.consent.client.common.decryptMessage
import org.wfanet.measurement.consent.client.common.encryptMessage
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toPublicKeyHandle
import org.wfanet.measurement.consent.client.common.verifySignedMessage

/** Computes the "requisition fingerprint" for [requisition]. */
fun computeRequisitionFingerprint(requisition: Requisition): ByteString {
  return Hashing.hashSha256(
    requisition.measurementSpec.message.value.concat(
      Hashing.hashSha256(requisition.encryptedRequisitionSpec.ciphertext)
    )
  )
}

/**
 * Verify the MeasurementSpec from the MeasurementConsumer.
 * 1. Validates [measurementConsumerCertificate] against [trustedIssuer]
 * 2. Verifies the [signature][SignedMessage.getSignature] of [signedMeasurementSpec] against its
 *    [data][SignedMessage.getData]
 * 3. TODO: Check for replay attacks for [signedMeasurementSpec]'s signature
 *
 * @throws CertPathValidatorException if [measurementConsumerCertificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
@Throws(CertPathValidatorException::class, SignatureException::class)
fun verifyMeasurementSpec(
  signedMeasurementSpec: SignedMessage,
  measurementConsumerCertificate: X509Certificate,
  trustedIssuer: X509Certificate,
) {
  measurementConsumerCertificate.run {
    validate(trustedIssuer)
    verifySignedMessage(signedMeasurementSpec)
  }
}

/**
 * Decrypts a signed [RequisitionSpec].
 *
 * @param encryptedSignedMessageRequisitionSpec an encrypted [SignedMessage] containing a
 *   [RequisitionSpec].
 * @param dataProviderPrivateKey the DataProvider's encryption private key.
 */
fun decryptRequisitionSpec(
  encryptedSignedMessageRequisitionSpec: EncryptedMessage,
  dataProviderPrivateKey: PrivateKeyHandle,
): SignedMessage {
  return dataProviderPrivateKey.decryptMessage(encryptedSignedMessageRequisitionSpec)
}

/**
 * Verifies [requisitionSpec] from the MeasurementConsumer.
 *
 * The steps are:
 * 1. TODO: Check for replay attacks
 * 2. Verify certificate path from [measurementConsumerCertificate] to [trustedIssuer]
 * 3. Verify the [signedRequisitionSpec] [signature][SignedMessage.getSignature]
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
  PublicKeyMismatchException::class,
)
fun verifyRequisitionSpec(
  signedRequisitionSpec: SignedMessage,
  requisitionSpec: RequisitionSpec,
  measurementSpec: MeasurementSpec,
  measurementConsumerCertificate: X509Certificate,
  trustedIssuer: X509Certificate,
) {
  measurementConsumerCertificate.validate(trustedIssuer)
  measurementConsumerCertificate.verifySignedMessage(signedRequisitionSpec)
  if (requisitionSpec.measurementPublicKey != measurementSpec.measurementPublicKey) {
    throw PublicKeyMismatchException("Measurement public key mismatch")
  }
  if (!measurementSpec.nonceHashesList.contains(Hashing.hashSha256(requisitionSpec.nonce))) {
    throw NonceMismatchException("Nonce hash mismatch")
  }
}

/**
 * Verifies the [signedElGamalPublicKey] from a Duchy.
 * 1. Validates the certificate path from [duchyCertificate] to [trustedDuchyIssuer]
 * 2. Verifies the [signedElGamalPublicKey] [signature][SignedMessage.getSignature]
 * 3. TODO: Check for replay attacks for the signature
 *
 * @throws CertPathValidatorException if [duchyCertificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
@Throws(CertPathValidatorException::class, SignatureException::class)
fun verifyElGamalPublicKey(
  signedElGamalPublicKey: SignedMessage,
  duchyCertificate: X509Certificate,
  trustedDuchyIssuer: X509Certificate,
) {
  duchyCertificate.run {
    validate(trustedDuchyIssuer)
    verifySignedMessage(signedElGamalPublicKey)
  }
}

/** Signs [result] using [dataProviderSigningKey] and [algorithm]. */
fun signResult(
  result: Measurement.Result,
  dataProviderSigningKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = dataProviderSigningKey.defaultAlgorithm,
): SignedMessage {
  return result.serializeAndSign(dataProviderSigningKey, algorithm)
}

/** Encrypts a [Metadata]. */
fun encryptMetadata(
  metadata: Metadata,
  measurementConsumerPublicKey: EncryptionPublicKey,
): EncryptedMessage =
  measurementConsumerPublicKey.toPublicKeyHandle().encryptMessage(metadata.pack())

/** Encrypts [signedResult] using [measurementConsumerPublicKey]. */
fun encryptResult(signedResult: SignedMessage, measurementConsumerPublicKey: EncryptionPublicKey) =
  measurementConsumerPublicKey.toPublicKeyHandle().encryptMessage(signedResult.pack())

/** Signs [randomSeed] using [dataProviderSigningKey] and [algorithm]. */
fun signRandomSeed(
  randomSeed: RandomSeed,
  dataProviderSigningKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = dataProviderSigningKey.defaultAlgorithm,
) = randomSeed.serializeAndSign(dataProviderSigningKey, algorithm)

/** Encrypts a signed [RandomSeed]. */
fun encryptRandomSeed(signedRandomSeed: SignedMessage, duchyPublicKey: EncryptionPublicKey) =
  duchyPublicKey.toPublicKeyHandle().encryptMessage(signedRandomSeed.pack())

/**
 * Verifies the [signeEncryptionPublicKey] from a Duchy.
 * 1. Validates the certificate path from [duchyCertificate] to [trustedDuchyIssuer]
 * 2. Verifies the [signeEncryptionPublicKey] [signature][SignedMessage.getSignature]
 * 3. TODO: Check for replay attacks for the signature
 *
 * @throws CertPathValidatorException if [duchyCertificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
fun verifyEncryptionPublicKey(
  signeEncryptionPublicKey: SignedMessage,
  duchyCertificate: X509Certificate,
  trustedDuchyIssuer: X509Certificate,
) {
  duchyCertificate.run {
    validate(trustedDuchyIssuer)
    verifySignedMessage(signeEncryptionPublicKey)
  }
}
