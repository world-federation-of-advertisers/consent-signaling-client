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
import java.security.PrivateKey
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.consent.crypto.hashSha256
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.sign
import org.wfanet.measurement.consent.crypto.signMessage

/**
 * Creates signature verifying EDP Participation.
 * 1. EDP computes the RequisitionFingerprint, which is the concatenation of a. The SHA-256 hash of
 * the encrypted RequisitionSpec b. The ParticipantListHash c. The serialized MeasurementSpec
 * 2. Signs the RequisitionFingerprint resulting in the participationSignature
 *
 * We assume the signed [requisition].measurementSpec was verified when the requisition was
 * initially received by the data provider.
 */
suspend fun createParticipationSignature(
  hybridCryptor: HybridCryptor,
  requisition: Requisition,
  privateKeyHandle: PrivateKeyHandle,
  dataProviderX509: ByteString
): SignedData {
  val encryptedRequisitionSpec = requisition.encryptedRequisitionSpec
  val requisitionSpec =
    RequisitionSpec.parseFrom(hybridCryptor.decrypt(privateKeyHandle, encryptedRequisitionSpec))
  // There is no salt when hashing the encrypted requisition spec
  val hashedEncryptedRequisitionSpec: ByteString = hashSha256(encryptedRequisitionSpec)
  val requisitionFingerprint =
    hashedEncryptedRequisitionSpec
      .concat(requireNotNull(requisitionSpec.dataProviderListHash))
      .concat(requireNotNull(requisition.measurementSpec.data))
  val dataProviderX509Certificate = readCertificate(dataProviderX509)
  val privateKey: PrivateKey =
    requireNotNull(privateKeyHandle.toJavaPrivateKey(dataProviderX509Certificate))
  val participationSignature =
    privateKey.sign(certificate = dataProviderX509Certificate, data = requisitionFingerprint)
  return SignedData.newBuilder()
    .apply {
      data = requisitionFingerprint
      signature = participationSignature
    }
    .build()
}

/** Signs the dataProvider's encryptionPublicKey. */
suspend fun signEncryptionPublicKey(
  encryptionPublicKey: EncryptionPublicKey,
  privateKeyHandle: PrivateKeyHandle,
  dataProviderX509: ByteString
): SignedData {
  return signMessage<EncryptionPublicKey>(
    message = encryptionPublicKey,
    privateKeyHandle = privateKeyHandle,
    certificate = readCertificate(dataProviderX509)
  )
}
