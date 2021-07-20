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
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.consent.crypto.hash
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
   * TODO Verify the dataProviderSignature has not been previously reused to protect against TODO
   * replay attacks
   */
  print("1:${requisition.requisitionSpecHash.joinToString()}\n")
  print("2:${hashedParticipantList.joinToString()}\n")
  print("3:${computation.measurementSpec.joinToString()}\n")
  print("4:${requisitionFingerprint.joinToString()}\n")
  return dataProviderX509.verifySignature(
    requisitionFingerprint,
    dataProviderParticipationSignature
  )
}
