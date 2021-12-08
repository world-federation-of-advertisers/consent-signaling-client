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

package org.wfanet.measurement.consent.client.measurementconsumer

import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement.Result as MeasurementResult
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.SigningKeyHandle
import org.wfanet.measurement.common.crypto.hashSha256
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.consent.crypto.getHybridCryptorForCipherSuite
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.signMessage

/** Create a SHA256 hash of the serialized [dataProviderList] using the [dataProviderListSalt]. */
fun createDataProviderListHash(
  dataProviderList: ByteString,
  dataProviderListSalt: ByteString
): ByteString {
  return hashSha256(dataProviderList.concat(dataProviderListSalt))
}

/**
 * Signs [requisitionSpec] into a [SignedData].
 *
 * The [measurementConsumerSigningKey] determines the algorithm type of the signature.
 */
fun signRequisitionSpec(
  requisitionSpec: RequisitionSpec,
  measurementConsumerSigningKey: SigningKeyHandle
): SignedData {
  return signMessage(requisitionSpec, measurementConsumerSigningKey)
}

/**
 * Encrypts the [SignedData] of the requisitionSpec using the specified [HybridCryptor] specified by
 * the [hybridEncryptionMapper].
 */
fun encryptRequisitionSpec(
  signedRequisitionSpec: SignedData,
  measurementPublicKey: EncryptionPublicKey,
  hybridEncryptionMapper: () -> HybridCryptor = ::getHybridCryptorForCipherSuite,
): ByteString {
  val hybridCryptor: HybridCryptor = hybridEncryptionMapper()
  return hybridCryptor.encrypt(measurementPublicKey, signedRequisitionSpec.toByteString())
}

/**
 * Signs [measurementSpec] into a [SignedData].
 *
 * [measurementConsumerSigningKey] determines the algorithm type of the signature.
 */
fun signMeasurementSpec(
  measurementSpec: MeasurementSpec,
  measurementConsumerSigningKey: SigningKeyHandle
): SignedData {
  return signMessage(measurementSpec, measurementConsumerSigningKey)
}

/** Signs the measurementConsumer's encryptionPublicKey. */
fun signEncryptionPublicKey(
  encryptionPublicKey: EncryptionPublicKey,
  signingKey: SigningKeyHandle
): SignedData {
  return signMessage(encryptionPublicKey, signingKey)
}

/**
 * Decrypts the [encryptedSignedDataResult] of the measurement results using the specified
 * [HybridCryptor] specified by the [hybridEncryptionMapper].
 */
suspend fun decryptResult(
  encryptedSignedDataResult: ByteString,
  measurementPrivateKeyHandle: PrivateKeyHandle,
  hybridEncryptionMapper: () -> HybridCryptor = ::getHybridCryptorForCipherSuite,
): SignedData {
  val hybridCryptor: HybridCryptor = hybridEncryptionMapper()
  return SignedData.parseFrom(
    hybridCryptor.decrypt(measurementPrivateKeyHandle, encryptedSignedDataResult)
  )
}

/**
 * Verify the Result from the Aggregator
 * 1. Verifies the [measurementResult] against the [resultSignature]
 * 2. TODO: Check for replay attacks for [resultSignature]
 * 3. TODO: Verify certificate chain for [aggregatorCertificate]
 */
fun verifyResult(
  resultSignature: ByteString,
  measurementResult: MeasurementResult,
  aggregatorCertificate: X509Certificate
): Boolean {
  return aggregatorCertificate.verifySignature(measurementResult.toByteString(), resultSignature)
}

/**
 * Verify the EncryptionPublicKey from the Endpoint Data Provider
 * 1. Verifies the [encryptionPublicKey] against the [encryptionPublicKeySignature]
 * 2. TODO: Check for replay attacks for [encryptionPublicKeySignature]
 * 3. TODO: Verify certificate chain for [edpCertificate]
 */
fun verifyEncryptionPublicKey(
  encryptionPublicKeySignature: ByteString,
  encryptionPublicKey: EncryptionPublicKey,
  edpCertificate: X509Certificate
): Boolean {
  return edpCertificate.verifySignature(
    encryptionPublicKey.toByteString(),
    encryptionPublicKeySignature
  )
}
