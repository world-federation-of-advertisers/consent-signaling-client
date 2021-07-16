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
import java.security.cert.X509Certificate
import java.security.PrivateKey
import org.wfanet.measurement.consent.crypto.hash
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.sign
import org.wfanet.measurement.consent.crypto.verifySignature
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.api.v2alpha.Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.system.v1alpha.Computation
import org.wfanet.measurement.system.v1alpha.Requisition

/**
 * Creates signature verifying EDP Participation. EDP computes the RequisitionFingerprint, which is
 * the concatenation of
 * 1. The SHA-256 hash of the encrypted RequisitionSpec
 * 2. The PartipantListHash
 * 3. The serialized MeasurementSpec
Signs the RequisitionFingerprint resulting in the EdpParticipationSignature
Sends the ElGamal encrypted Sketch and the EdpParticipationSignature to its preferred (or a random) Duchy.

 */
fun verifyEdpParticipationSignature(
  measurement: Measurement,
  requisition: Requisition,
  dataProviderCertificate: Certificate
): Boolean {
  // TODO: Verify Data Provider Certificate (is from root authority)

  // Get the Signature...
  val signature = requisition.dataProviderParticipationSignature
  // Generate the Data Provider List Hash
  val dataProviderListHash: ByteString =
    hash(computation.dataProviderList, computation.dataProviderListSalt)
  // Calculate the Requisition Fingerprint
  val requisitionFingerprint =
    ByteString.copyFrom(
      requisition
        .requisitionSpecHash
        .toByteArray()
        .plus(dataProviderListHash.toByteArray())
        .plus(computation.measurementSpec.toByteArray())
    )
  val dataProviderX509:X509Certificate = readCertificate(dataProviderCertificate.x509Der)

  // TODO Verify the EdpParticipantSignature has not been previously reused to protect against
  // replay attacks
  return dataProviderX509.verifySignature(requisitionFingerprint, signature)
}

/**
 * Sign and encrypts the [measurementResult] into a serialized [SignedData] ProtoBuf. The
 * [aggregatorCertificate] is required to determine the algorithm type of the signature
 */
fun signAndEncryptResult(
  hybridCryptor: HybridCryptor,
  measurementResult: Measurement.Result,
  duchyPrivateKeyHandle: PrivateKeyHandle,
  aggregatorCertificate: Certificate,
  measurementPublicKey: EncryptionPublicKey
): ByteString {
  val privateKey:PrivateKey = requireNotNull(duchyPrivateKeyHandle.toJavaPrivateKey())
  // Sign the result with the private key
  val aggregatorX509:X509Certificate = readCertificate(aggregatorCertificate.x509Der)
  val measurementSignature =
    privateKey.sign(aggregatorX509, data = measurementResult.toByteString())

  // Create the SignedData
  val signedData =
    SignedData.newBuilder()
      .also {
        it.data = measurementResult.toByteString()
        it.signature = measurementSignature
      }
      .build()
  // Encrypt the SignedData
  return hybridCryptor.encrypt(measurementPublicKey, ByteString.copyFrom(signedData.toByteArray()))
}
