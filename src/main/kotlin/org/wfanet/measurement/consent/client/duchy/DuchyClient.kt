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
import org.wfanet.measurement.consent.crypto.hash
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.sign
import org.wfanet.measurement.consent.crypto.verifySignature

data class Computation(
  val dataProviderList: ByteString,
  val dataProviderListSalt: ByteString,
  val measurementSpec: ByteString,
  val encryptedRequisitionSpec: ByteString,
)

data class Requisition(
  val dataProviderCertificate: ByteString,
  val requisitionSpecHash: ByteString
)

/**
 * For each EDP it receives input from:
 * 1. Independently rebuilds the requisitionFingerprint with data from Kingdom
 * 2. Verifies the EdpParticipationSignature against the fingerprint
 * 3. TODO: Check for replay attacks
 */
fun verifyDataProviderParticipation(
  dataProviderParticipationSignature: ByteString,
  requisition: Requisition,
  computation: Computation
): Boolean {
  val hashedParticipantList: ByteString =
    hash(computation.dataProviderList, computation.dataProviderListSalt)
  val requisitionFingerprint =
    requireNotNull(requisition.requisitionSpecHash)
      .concat(hashedParticipantList)
      .concat(requireNotNull(computation.measurementSpec))

  // TODO: Verify DataProviderPublicKey is properly signed
  val dataProviderX509: X509Certificate = readCertificate(requisition.dataProviderCertificate)

  /**
   * TODO Verify the dataProviderSignature has not been previously reused to protect against replay
   * attacks
   */
  return dataProviderX509.verifySignature(
    requisitionFingerprint,
    dataProviderParticipationSignature
  )
}

/**
 * Sign and encrypts the [measurementResult] into a serialized [SignedData] ProtoBuf. The
 * [aggregatorCertificate] is required to determine the algorithm type of the signature
 */
fun signAndEncryptResult(
  hybridCryptor: HybridCryptor,
  measurementResult: ByteString,
  privateKeyHandle: PrivateKeyHandle,
  aggregatorCertificate: ByteString,
  measurementPublicKey: EncryptionPublicKey
): ByteString {
  val privateKey: PrivateKey = requireNotNull(privateKeyHandle.toJavaPrivateKey("EC"))
  val measurementSignature =
    privateKey.sign(certificate = readCertificate(aggregatorCertificate), data = measurementResult)
  val signedData =
    SignedData.newBuilder()
      .also {
        it.data = measurementResult
        it.signature = measurementSignature
      }
      .build()
  return hybridCryptor.encrypt(measurementPublicKey, ByteString.copyFrom(signedData.toByteArray()))
}
