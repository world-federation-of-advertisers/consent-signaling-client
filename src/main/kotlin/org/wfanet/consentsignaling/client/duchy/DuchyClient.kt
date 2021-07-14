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

package org.wfanet.consentsignaling.client.duchy

import com.google.protobuf.ByteString
import org.wfanet.consentsignaling.crypto.hash.generateDataProviderListHash
import org.wfanet.consentsignaling.crypto.hybridencryption.HybridCryptor
import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.consentsignaling.crypto.signage.Signer
import org.wfanet.measurement.api.v2alpha.Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.system.v1alpha.Computation
import org.wfanet.measurement.system.v1alpha.Requisition

/**
 * Verifies the EDP Participation using the Duchy's Computation and Requisition against the
 * DataProviderCertificate
 */
fun verifyEdpParticipationSignature(
  signer: Signer,
  computation: Computation,
  requisition: Requisition,
  dataProviderCertificate: Certificate
): Boolean {
  // TODO: Verify Data Provider Certificate (is from root authority)

  // Get the Signature...
  val signature = requisition.dataProviderParticipationSignature
  // Generate the Data Provider List Hash
  val dataProviderListHash: ByteString =
    generateDataProviderListHash(computation.dataProviderList, computation.dataProviderListSalt)
  // Calculate the Requisition Fingerprint
  val requisitionFingerprint =
    ByteString.copyFrom(
      requisition
        .requisitionSpecHash
        .toByteArray()
        .plus(dataProviderListHash.toByteArray())
        .plus(computation.measurementSpec.toByteArray())
    )

  // TODO Verify the EdpParticipantSignature has not been previously reused to protect against
  // replay attacks

  return signer.verify(dataProviderCertificate, signature, requisitionFingerprint)
}

/**
 * Sign and encrypts the Result into a serialized SignedData ProtoBuf. The aggregator certificate is
 * required to determine the algorithm type of the signature
 */
fun signAndEncryptResult(
  signer: Signer,
  hybridCryptor: HybridCryptor,
  result: Measurement.Result,
  duchyPrivateKeyHandle: PrivateKeyHandle,
  aggregatorCertificate: Certificate,
  measurementPublicKey: EncryptionPublicKey
): ByteString {
  // Sign the result with the private key
  val measurementSignature =
    signer.sign(aggregatorCertificate, duchyPrivateKeyHandle, result.toByteString())

  // Create the SignedData
  val signedData =
    SignedData.newBuilder()
      .also {
        it.data = result.toByteString()
        it.signature = measurementSignature
      }
      .build()
  // Encrypt the SignedData
  return hybridCryptor.encrypt(measurementPublicKey, ByteString.copyFrom(signedData.toByteArray()))
}
