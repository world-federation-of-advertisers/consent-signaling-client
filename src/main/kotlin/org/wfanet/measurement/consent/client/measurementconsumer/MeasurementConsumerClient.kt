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
import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.EventGroup.Metadata
import org.wfanet.measurement.api.v2alpha.Measurement.Result as MeasurementResult
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.Hashing
import org.wfanet.measurement.common.crypto.PrivateKeyHandle
import org.wfanet.measurement.common.crypto.SignatureAlgorithm
import org.wfanet.measurement.common.crypto.SigningKeyHandle
import org.wfanet.measurement.common.crypto.validate
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toPublicKeyHandle
import org.wfanet.measurement.consent.client.common.verifySignedData

/** Create a SHA256 hash of the serialized [dataProviderList] using the [dataProviderListSalt]. */
fun createDataProviderListHash(
  dataProviderList: ByteString,
  dataProviderListSalt: ByteString
): ByteString {
  return Hashing.hashSha256(dataProviderList.concat(dataProviderListSalt))
}

/**
 * Signs [requisitionSpec] into a [SignedData].
 *
 * The [measurementConsumerSigningKey] determines the algorithm type of the signature.
 */
fun signRequisitionSpec(
  requisitionSpec: RequisitionSpec,
  measurementConsumerSigningKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = measurementConsumerSigningKey.defaultAlgorithm
): SignedData {
  return requisitionSpec.serializeAndSign(measurementConsumerSigningKey, algorithm)
}

/**
 * Encrypts a signed [RequisitionSpec].
 *
 * @param signedRequisitionSpec a [SignedData] containing a [RequisitionSpec]
 */
fun encryptRequisitionSpec(
  signedRequisitionSpec: SignedData,
  measurementPublicKey: EncryptionPublicKey
): ByteString {
  return measurementPublicKey
    .toPublicKeyHandle()
    .hybridEncrypt(signedRequisitionSpec.toByteString())
}

/**
 * Signs [measurementSpec] into a [SignedData].
 *
 * [measurementConsumerSigningKey] determines the algorithm type of the signature.
 */
fun signMeasurementSpec(
  measurementSpec: MeasurementSpec,
  measurementConsumerSigningKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = measurementConsumerSigningKey.defaultAlgorithm
): SignedData {
  return measurementSpec.serializeAndSign(measurementConsumerSigningKey, algorithm)
}

/** Signs the measurementConsumer's encryptionPublicKey. */
fun signEncryptionPublicKey(
  encryptionPublicKey: EncryptionPublicKey,
  signingKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = signingKey.defaultAlgorithm
): SignedData {
  return encryptionPublicKey.serializeAndSign(signingKey, algorithm)
}

/**
 * Decrypts the encrypted signed [MeasurementResult].
 *
 * @param encryptedSignedDataResult an encrypted [SignedData] containing a [MeasurementResult].
 * @param measurementPrivateKey the encryption private key matching the Measurement public key.
 */
fun decryptResult(
  encryptedSignedDataResult: ByteString,
  measurementPrivateKey: PrivateKeyHandle
): SignedData {
  return SignedData.parseFrom(measurementPrivateKey.hybridDecrypt(encryptedSignedDataResult))
}

/**
 * Verifies a [MeasurementResult] from a DataProvider or the Aggregator
 * 1. Validates [certificate] against [trustedIssuer]
 * 2. Verifies the [signedResult] data against the [signedResult] signature
 * 3. TODO: Check for replay attacks for the [signedResult] signature
 *
 * @throws CertPathValidatorException if [certificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
fun verifyResult(
  signedResult: SignedData,
  certificate: X509Certificate,
  trustedIssuer: X509Certificate
) {
  certificate.run {
    validate(trustedIssuer)
    verifySignedData(signedResult)
  }
}

/**
 * Verifies the EncryptionPublicKey from the DataProvider
 * 1. Validates the certificate path from [dataProviderCertificate] to [trustedIssuer]
 * 2. Verifies the [signature][SignedData.getSignature] of [signedEncryptionPublicKey] against its
 *    [data][SignedData.getData]
 * 3. TODO: Check for replay attacks for [dataProviderCertificate]'s signature
 *
 * @throws CertPathValidatorException if [dataProviderCertificate] is invalid
 * @throws SignatureException if the signature is invalid
 */
@Throws(CertPathValidatorException::class, SignatureException::class)
fun verifyEncryptionPublicKey(
  signedEncryptionPublicKey: SignedData,
  dataProviderCertificate: X509Certificate,
  trustedIssuer: X509Certificate
) {
  dataProviderCertificate.run {
    validate(trustedIssuer)
    verifySignedData(signedEncryptionPublicKey)
  }
}

/** Decrypts an encrypted [Metadata]. */
fun decryptMetadata(
  encryptedMetadata: ByteString,
  measurementConsumerPrivateKey: PrivateKeyHandle
): Metadata = Metadata.parseFrom(measurementConsumerPrivateKey.hybridDecrypt(encryptedMetadata))
