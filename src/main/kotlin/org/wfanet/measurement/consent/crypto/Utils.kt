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

package org.wfanet.measurement.consent.crypto

import com.google.protobuf.Message
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.ExchangeStep
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle

/** Generic for signing [Protobuf] messages. Used by client functions to show consent. */
suspend fun <T : Message> signMessage(
  message: T,
  privateKeyHandle: PrivateKeyHandle,
  certificate: X509Certificate,
): SignedData {
  val messageData = message.toByteString()
  val messageSignature = privateKeyHandle.sign(messageData)
  return SignedData.newBuilder()
    .apply {
      data = messageData
      signature = messageSignature
    }
    .build()
}

/**
 * Verifies that the [signedExchangeWorkflow] was signed by both the entities represented by
 * [modelProviderCertificate] and [dataProviderCertificate]
 */
fun verifyExchangeStepSignatures(
  signedExchangeWorkflow: ExchangeStep.SignedExchangeWorkflow,
  modelProviderCertificate: X509Certificate,
  dataProviderCertificate: X509Certificate,
): Boolean {
  val signedData = signedExchangeWorkflow.serializedExchangeWorkflow
  val hasModelProviderSignature =
    modelProviderCertificate.verifySignature(
      signedData,
      signedExchangeWorkflow.modelProviderSignature
    )
  val hasDataProviderSignature =
    dataProviderCertificate.verifySignature(
      signedData,
      signedExchangeWorkflow.dataProviderSignature
    )
  return hasModelProviderSignature && hasDataProviderSignature
}
