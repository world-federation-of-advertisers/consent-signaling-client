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

package org.wfanet.measurement.consent.testing

import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.Test
import org.wfanet.measurement.api.v2alpha.ExchangeStep
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.common.crypto.testing.KEY_ALGORITHM
import org.wfanet.measurement.consent.crypto.sign

private val DATA = ByteString.copyFromUtf8("I am some data to be double signed")
private val RANDOM_SIGNATURE = ByteString.copyFromUtf8("some random certificate signature")

typealias verifyExchangeStepSignaturesFunction =
  (ExchangeStep.SignedExchangeWorkflow, X509Certificate, X509Certificate) -> Boolean

abstract class AbstractExchangeStepSignaturesFunctionTest {
  abstract val verifyExchangeStepSignatures: verifyExchangeStepSignaturesFunction

  @Test
  fun `verifyExchangeStepSignatures returns false for having only an MC valid signature`() {
    val mcPrivateKey = readPrivateKey(MC_1_KEY_FILE, KEY_ALGORITHM)
    val mcCertificate: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
    val edpCertificate: X509Certificate = readCertificate(EDP_1_CERT_PEM_FILE)
    val mcSignature = mcPrivateKey.sign(mcCertificate, DATA)
    val exchangeWorkflow =
      ExchangeStep.SignedExchangeWorkflow.newBuilder()
        .apply {
          serializedExchangeWorkflow = DATA
          modelProviderSignature = mcSignature
          dataProviderSignature = RANDOM_SIGNATURE
        }
        .build()
    assertFalse(verifyExchangeStepSignatures(exchangeWorkflow, mcCertificate, edpCertificate))
  }

  @Test
  fun `verifyExchangeStepSignatures returns false for having only an EDP valid signature`() {
    val edpPrivateKey = readPrivateKey(EDP_1_KEY_FILE, KEY_ALGORITHM)
    val edpCertificate: X509Certificate = readCertificate(EDP_1_CERT_PEM_FILE)
    val mcCertificate: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
    val edpSignature = edpPrivateKey.sign(edpCertificate, DATA)
    val exchangeWorkflow =
      ExchangeStep.SignedExchangeWorkflow.newBuilder()
        .apply {
          serializedExchangeWorkflow = DATA
          modelProviderSignature = RANDOM_SIGNATURE
          dataProviderSignature = edpSignature
        }
        .build()
    assertFalse(verifyExchangeStepSignatures(exchangeWorkflow, mcCertificate, edpCertificate))
  }

  @Test
  fun `verifyExchangeStepSignatures returns true when both signatures are valid`() {
    val mcPrivateKey = readPrivateKey(MC_1_KEY_FILE, KEY_ALGORITHM)
    val mcCertificate: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
    val edpPrivateKey = readPrivateKey(EDP_1_KEY_FILE, KEY_ALGORITHM)
    val edpCertificate: X509Certificate = readCertificate(EDP_1_CERT_PEM_FILE)
    val mcSignature = mcPrivateKey.sign(mcCertificate, DATA)
    val edpSignature = edpPrivateKey.sign(edpCertificate, DATA)
    val exchangeWorkflow =
      ExchangeStep.SignedExchangeWorkflow.newBuilder()
        .apply {
          serializedExchangeWorkflow = DATA
          modelProviderSignature = mcSignature
          dataProviderSignature = edpSignature
        }
        .build()
    assertTrue(verifyExchangeStepSignatures(exchangeWorkflow, mcCertificate, edpCertificate))
  }
}
