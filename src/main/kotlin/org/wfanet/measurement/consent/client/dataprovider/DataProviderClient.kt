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
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.consent.crypto.hash
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.sign

/**
 * Creates signature verifying EDP Participation.
 * 1. EDP computes the RequisitionFingerprint, which is the concatenation of a. The SHA-256 hash of
 * the encrypted RequisitionSpec b. The ParticipantListHash c. The serialized MeasurementSpec
 * 2. Signs the RequisitionFingerprint resulting in the participationSignature
 */
fun indicateRequisitionParticipation(
  hybridCryptor: HybridCryptor,
  requisition: Requisition,
  privateKeyHandle: PrivateKeyHandle,
  dataProviderListSalt: ByteString,
  dataProviderX509: ByteString
): SignedData {
  val encryptedRequisitionSpec = requisition.encryptedRequisitionSpec
  val requisitionSpec =
    RequisitionSpec.parseFrom(hybridCryptor.decrypt(privateKeyHandle, encryptedRequisitionSpec))
  val hashedEncryptedRequisitionSpec: ByteString =
    hash(encryptedRequisitionSpec, dataProviderListSalt)
  val requisitionFingerprint =
    hashedEncryptedRequisitionSpec
      .concat(requireNotNull(requisitionSpec.dataProviderListHash))
      /**
       * We assume the signed measurementSpec was verified when the requisition was initially
       * received by the data provider.
       */
      .concat(requireNotNull(requisition.measurementSpec.data))
  print("1:${hashedEncryptedRequisitionSpec.joinToString()}\n")
  print("2:${requisitionSpec.dataProviderListHash.joinToString()}\n")
  print("3:${requisition.measurementSpec.data.joinToString()}\n")
  print("4:${requisitionFingerprint.joinToString()}\n")
  val privateKey: PrivateKey = requireNotNull(privateKeyHandle.toJavaPrivateKey("EC"))
  val participationSignature =
    privateKey.sign(certificate = readCertificate(dataProviderX509), data = requisitionFingerprint)
  return SignedData.newBuilder()
    .also {
      it.data = requisitionFingerprint
      it.signature = participationSignature
    }
    .build()
}
