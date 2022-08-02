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
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.SigningKeyHandle
import org.wfanet.measurement.common.crypto.hashSha256
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.consent.client.common.signMessage
import org.wfanet.measurement.consent.client.common.toPublicKeyHandle

/** Data about a Requisition that Duchy received from Kingdom. */
data class Requisition(
  /** Pre-computed requisition fingerprint. */
  val requisitionFingerprint: ByteString,
  /** SHA256 hash of nonce. */
  val nonceHash: ByteString
)

/** Computes the "requisition fingerprint" for a requisition. */
fun computeRequisitionFingerprint(
  serializedMeasurementSpec: ByteString,
  requisitionSpecHash: ByteString
): ByteString {
  return hashSha256(serializedMeasurementSpec.concat(requisitionSpecHash))
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
  nonce: Long
): Boolean {
  val nonceHash = hashSha256(nonce)
  return requisitionFingerprint == requisition.requisitionFingerprint &&
    nonceHash == requisition.nonceHash &&
    measurementSpec.nonceHashesList.contains(nonceHash)
}

/** Verifies that all expected DataProviders have participated in the Computation. */
fun verifyDataProviderParticipation(
  measurementSpec: MeasurementSpec,
  nonces: Iterable<Long>
): Boolean {
  val computedNonceHashes = nonces.map { hashSha256(it) }.toSet()
  return measurementSpec.nonceHashesCount == computedNonceHashes.size &&
    computedNonceHashes.containsAll(measurementSpec.nonceHashesList)
}

/** Signs [measurementResult] into a [SignedData] using [aggregatorSigningKey]. */
fun signResult(
  measurementResult: Measurement.Result,
  aggregatorSigningKey: SigningKeyHandle
): SignedData {
  return signMessage(measurementResult, aggregatorSigningKey)
}

/** Encrypts the signed [Measurement.Result]. */
fun encryptResult(
  signedResult: SignedData,
  measurementPublicKey: EncryptionPublicKey,
): ByteString {
  return measurementPublicKey.toPublicKeyHandle().hybridEncrypt(signedResult.toByteString())
}

/** Signs [elGamalPublicKey] into a [SignedData] using [duchySigningKey]. */
fun signElgamalPublicKey(
  elGamalPublicKey: ElGamalPublicKey,
  duchySigningKey: SigningKeyHandle
): SignedData {
  return signMessage(elGamalPublicKey, duchySigningKey)
}

/**
 * Verify the [elGamalPublicKeySignature] from another duchy.
 * 1. Verifies the [elGamalPublicKey] against the [elGamalPublicKeySignature]
 * 2. TODO: Check for replay attacks for [elGamalPublicKeySignature]
 * 3. TODO: Verify certificate chain for [duchyCertificate]
 */
fun verifyElGamalPublicKey(
  elGamalPublicKeyData: ByteString,
  elGamalPublicKeySignature: ByteString,
  duchyCertificate: X509Certificate
): Boolean {
  return duchyCertificate.verifySignature(elGamalPublicKeyData, elGamalPublicKeySignature)
}
