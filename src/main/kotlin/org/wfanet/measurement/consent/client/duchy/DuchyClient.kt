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
import java.security.PrivateKey
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.consent.crypto.hashSha256
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.sign
import org.wfanet.measurement.consent.crypto.verifySignature

// Fields from the computationDetails proto of the internal duchy api
data class Computation(
  // Serialized `DataProviderList`.
  val dataProviderList: ByteString,
  // Salt for SHA256 hash of `dataProviderList`.
  val dataProviderListSalt: ByteString,
  // Serialized `MeasurementSpec`.
  val measurementSpec: ByteString
)

// Fields from the requisitionDetails proto of the internal duchy api
data class Requisition(
  // X.509 certificate in DER format which can be verified using the `DataProvider`'s root
  // certificate.
  val dataProviderCertificate: ByteString,
  // SHA256 hash of encrypted `RequisitionSpec`.
  val requisitionSpecHash: ByteString
)

/**
 * For each EDP it receives input from:
 * 1. Independently rebuilds the requisitionFingerprint with data from Kingdom
 * 2. Verifies the EdpParticipationSignature against the fingerprint
 * 3. TODO: Check for replay attacks
 */
suspend fun verifyDataProviderParticipation(
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

  // TODO: Verify Certificate Chain
  val dataProviderX509: X509Certificate = readCertificate(requisition.dataProviderCertificate)

  // TODO Verify the dataProviderSignature has not been previously reused to protect against replay
  // attacks
  return dataProviderX509.verifySignature(
    requisitionFingerprint,
    dataProviderParticipationSignature
  )
}

/**
 * Sign and encrypts the [measurementResult] into a serialized [SignedData] ProtoBuf. The
 * [aggregatorCertificate] is required to determine the algorithm type of the signature
 */
suspend fun signAndEncryptResult(
  hybridCryptor: HybridCryptor,
  measurementResult: ByteString,
  privateKeyHandle: PrivateKeyHandle,
  aggregatorCertificate: ByteString,
  duchyCertificate: ByteString,
  measurementPublicKey: EncryptionPublicKey
): ByteString {
  val privateKey: PrivateKey =
    requireNotNull(privateKeyHandle.toJavaPrivateKey(readCertificate(duchyCertificate)))
  val measurementSignature =
    privateKey.sign(certificate = readCertificate(aggregatorCertificate), data = measurementResult)
  val signedData =
    SignedData.newBuilder()
      .apply {
        data = measurementResult
        signature = measurementSignature
      }
      .build()
  return hybridCryptor.encrypt(measurementPublicKey, ByteString.copyFrom(signedData.toByteArray()))
}
