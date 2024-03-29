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

package org.wfanet.measurement.consent.client.duchy

import com.google.protobuf.ByteString
import java.nio.ByteOrder
import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.EncryptedMessage
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.RandomSeed
import org.wfanet.measurement.api.v2alpha.SignedMessage
import org.wfanet.measurement.common.crypto.Hashing
import org.wfanet.measurement.common.crypto.PrivateKeyHandle
import org.wfanet.measurement.common.crypto.SignatureAlgorithm
import org.wfanet.measurement.common.crypto.SigningKeyHandle
import org.wfanet.measurement.common.crypto.validate
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.common.pack
import org.wfanet.measurement.consent.client.common.decryptMessage
import org.wfanet.measurement.consent.client.common.encryptMessage
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toPublicKeyHandle
import org.wfanet.measurement.consent.client.common.verifySignedMessage

/** Data about a Requisition that Duchy received from Kingdom. */
data class Requisition(
  /** Pre-computed requisition fingerprint. */
  val requisitionFingerprint: ByteString,
  /** SHA256 hash of nonce. */
  val nonceHash: ByteString,
)

/** Computes the "requisition fingerprint" for a requisition. */
fun computeRequisitionFingerprint(
  serializedMeasurementSpec: ByteString,
  requisitionSpecHash: ByteString,
): ByteString {
  return Hashing.hashSha256(serializedMeasurementSpec.concat(requisitionSpecHash))
}

/**
 * Verifies the parameters that an EDP passes when fulfilling a Requisition.
 *
 * @param measurementSpec [MeasurementSpec] retrieved from Kingdom
 * @param requisition data about the Requisition retrieved from Kingdom
 *
 * The steps are:
 * 1. Compare the requisition fingerprint to the one independently computed from Kingdom data.
 * 2. Compute the hash of the nonce and compare it to the one from the Kingdom.
 * 3. Verify that the list in [measurementSpec] contains the nonce hash.
 */
fun verifyRequisitionFulfillment(
  measurementSpec: MeasurementSpec,
  requisition: Requisition,
  requisitionFingerprint: ByteString,
  nonce: Long,
): Boolean {
  val nonceHash = Hashing.hashSha256(nonce, ByteOrder.BIG_ENDIAN)
  return requisitionFingerprint == requisition.requisitionFingerprint &&
    nonceHash == requisition.nonceHash &&
    measurementSpec.nonceHashesList.contains(nonceHash)
}

/** Verifies that all expected DataProviders have participated in the Computation. */
fun verifyDataProviderParticipation(
  measurementSpec: MeasurementSpec,
  nonces: Iterable<Long>,
): Boolean {
  val computedNonceHashes = nonces.map { Hashing.hashSha256(it, ByteOrder.BIG_ENDIAN) }.toSet()
  return measurementSpec.nonceHashesCount == computedNonceHashes.size &&
    computedNonceHashes.containsAll(measurementSpec.nonceHashesList)
}

/** Signs [measurementResult] into a [SignedMessage] using [aggregatorSigningKey]. */
fun signResult(
  measurementResult: Measurement.Result,
  aggregatorSigningKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = aggregatorSigningKey.defaultAlgorithm,
): SignedMessage {
  return measurementResult.serializeAndSign(aggregatorSigningKey, algorithm)
}

/** Encrypts the signed [Measurement.Result]. */
fun encryptResult(
  signedResult: SignedMessage,
  measurementPublicKey: EncryptionPublicKey,
): EncryptedMessage {
  return measurementPublicKey.toPublicKeyHandle().encryptMessage(signedResult.pack())
}

/** Signs [elGamalPublicKey] into a [SignedMessage] using [duchySigningKey]. */
fun signElgamalPublicKey(
  elGamalPublicKey: ElGamalPublicKey,
  duchySigningKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = duchySigningKey.defaultAlgorithm,
): SignedMessage {
  return elGamalPublicKey.serializeAndSign(duchySigningKey, algorithm)
}

/**
 * Verifies the [elGamalPublicKeySignature] from a Duchy.
 * 1. Validates [duchyCertificate] against [trustedDuchyIssuer]
 * 2. Verifies the [elGamalPublicKeyData] against the [elGamalPublicKeySignature]
 * 3. TODO: Check for replay attacks for [elGamalPublicKeySignature]
 *
 * @throws CertPathValidatorException if [duchyCertificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
fun verifyElGamalPublicKey(
  elGamalPublicKeyData: ByteString,
  elGamalPublicKeySignature: ByteString,
  signatureAlgorithm: SignatureAlgorithm,
  duchyCertificate: X509Certificate,
  trustedDuchyIssuer: X509Certificate,
) {
  return duchyCertificate.run {
    validate(trustedDuchyIssuer)

    if (!verifySignature(signatureAlgorithm, elGamalPublicKeyData, elGamalPublicKeySignature)) {
      throw SignatureException("Signature is invalid")
    }
  }
}

/** Signs the Duchy's encryptionPublicKey. */
fun signEncryptionPublicKey(
  encryptionPublicKey: EncryptionPublicKey,
  signingKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = signingKey.defaultAlgorithm,
): SignedMessage {
  return encryptionPublicKey.serializeAndSign(signingKey, algorithm)
}

/** Decrypt the encrypted signed [RandomSeed] */
fun decryptRandomSeed(
  encryptedSignedRandomSeed: EncryptedMessage,
  duchyPrivateKey: PrivateKeyHandle,
): SignedMessage {
  return duchyPrivateKey.decryptMessage(encryptedSignedRandomSeed)
}

/**
 * Verifies a [RandomSeed] from a DataProvider passed through another Duchy.
 * 1. Validates [certificate] against [trustedIssuer]
 * 2. Verifies the [signedRandomSeed] data against the [signedRandomSeed] signature
 *
 * @throws CertPathValidatorException if [certificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
fun verifyRandomSeed(
  signedRandomSeed: SignedMessage,
  dataProviderCertificate: X509Certificate,
  trustedIssuer: X509Certificate,
) {
  dataProviderCertificate.run {
    validate(trustedIssuer)
    verifySignedMessage(signedRandomSeed)
  }
}
