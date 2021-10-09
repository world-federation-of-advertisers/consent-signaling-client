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
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.consent.crypto.hashSha256
import org.wfanet.measurement.consent.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.keys.PublicKeyHandle
import org.wfanet.measurement.consent.crypto.signMessage
import org.wfanet.measurement.consent.crypto.verifySignature

/** Fields from the computationDetails proto of the internal duchy api */
data class Computation(
  /** Serialized `DataProviderList`. */
  val dataProviderList: ByteString,
  /** Salt for SHA256 hash of `dataProviderList`. */
  val dataProviderListSalt: ByteString,
  /** Serialized `MeasurementSpec`. */
  val measurementSpec: ByteString
)

/** Fields from the requisitionDetails proto of the internal duchy api */
data class Requisition(
  /**
   * X.509 certificate in DER format which can be verified using the `DataProvider`'s root
   * certificate.
   */
  val dataProviderCertificate: X509Certificate,
  /** SHA256 hash of encrypted `RequisitionSpec`. */
  val requisitionSpecHash: ByteString
)

/**
 * For each EDP it receives input from:
 * 1. Independently rebuilds the requisitionFingerprint with data from Kingdom
 * 2. Verifies the EdpParticipationSignature against the fingerprint
 * 3. TODO: Check for replay attacks for dataProviderParticipationSignature
 * 4. TODO: Verify certificate chain for requisition.dataProviderCertificate
 */
fun verifyDataProviderParticipation(
  dataProviderParticipationSignature: ByteString,
  requisition: Requisition,
  computation: Computation
): Boolean {
  val hashedParticipantList: ByteString =
    hashSha256(computation.dataProviderList, computation.dataProviderListSalt)
  val requisitionFingerprint =
    requireNotNull(requisition.requisitionSpecHash)
      .concat(hashedParticipantList)
      .concat(requireNotNull(computation.measurementSpec))
  return requisition.dataProviderCertificate.verifySignature(
    requisitionFingerprint,
    dataProviderParticipationSignature
  )
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
 * Encrypts the [SignedData] of the measurement results using the specified [measurementPublicKey]
 */
suspend fun encryptResult(
  signedResult: SignedData,
  measurementPublicKey: EncryptionPublicKey,
): ByteString {
  return PublicKeyHandle.fromEncryptionPublicKey(measurementPublicKey)
      .encrypt(signedResult.toByteString())
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
