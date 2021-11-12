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
import org.wfanet.measurement.api.v2alpha.Measurement.Result as MeasurementResult
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.hashSha256
import org.wfanet.measurement.consent.crypto.getHybridCryptorForCipherSuite
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.signMessage
import org.wfanet.measurement.consent.crypto.verifySignature

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

/**
 * Signs [measurementResult] into a [SignedData] ProtoBuf. The [aggregatorCertificate] is required
 * to determine the algorithm type of the signature
 */
suspend fun signResult(
  measurementResult: MeasurementResult,
  /** This private key is paired with the [aggregatorCertificate] */
  aggregatorKeyHandle: PrivateKeyHandle,
  aggregatorCertificate: X509Certificate
): SignedData {
  return signMessage(
    message = measurementResult,
    privateKeyHandle = aggregatorKeyHandle,
    certificate = aggregatorCertificate
  )
}

/**
 * Encrypts the [SignedData] of the measurement results using the specified [HybridCryptor]
 * specified by [hybridEncryptionMapper].
 */
fun encryptResult(
  signedResult: SignedData,
  measurementPublicKey: EncryptionPublicKey,
  hybridEncryptionMapper: () -> HybridCryptor = ::getHybridCryptorForCipherSuite,
): ByteString {
  val hybridCryptor: HybridCryptor = hybridEncryptionMapper()
  return hybridCryptor.encrypt(measurementPublicKey, signedResult.toByteString())
}

/**
 * Signs [elgamalPublicKey] into a [SignedData] ProtoBuf. The [duchyCertificate] is required to
 * determine the algorithm type of the signature
 */
suspend fun signElgamalPublicKey(
  elgamalPublicKey: ElGamalPublicKey,
  /** This private key is paired with the [duchyCertificate] */
  duchyKeyHandle: PrivateKeyHandle,
  duchyCertificate: X509Certificate
): SignedData {
  return signMessage(
    message = elgamalPublicKey,
    privateKeyHandle = duchyKeyHandle,
    certificate = duchyCertificate
  )
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
