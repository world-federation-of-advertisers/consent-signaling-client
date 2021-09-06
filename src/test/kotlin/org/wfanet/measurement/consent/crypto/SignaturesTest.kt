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

import com.google.common.collect.Range
import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import kotlin.random.Random
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.ExchangeStep
import org.wfanet.measurement.common.asBufferedFlow
import org.wfanet.measurement.common.toByteString
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.common.crypto.testing.FIXED_SERVER_CERT_PEM_FILE as SERVER_CERT_PEM_FILE
import org.wfanet.measurement.common.crypto.testing.FIXED_SERVER_KEY_FILE as SERVER_KEY_FILE
import org.wfanet.measurement.common.crypto.testing.KEY_ALGORITHM
import org.wfanet.measurement.common.flatten
import org.wfanet.measurement.consent.crypto.exception.InvalidSignatureException
import org.wfanet.measurement.consent.testing.EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_KEY_FILE
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE

private val DATA = ByteString.copyFromUtf8("I am some data to sign")
private val LONG_DATA =
  ByteString.copyFromUtf8("I am some data to sign. I am some data to sign. I am some data to sign.")
private val ALT_DATA = ByteString.copyFromUtf8("I am some alternative data")

// TODO: Consider migrating this to common-jvm if the underlying issue isn't solved.
// kotlinx.coroutines.test.runBlockingTest complains about
// "java.lang.IllegalStateException: This job has not completed yet".
// This is a common issue: https://github.com/Kotlin/kotlinx.coroutines/issues/1204.
private fun runBlockingTest(block: suspend CoroutineScope.() -> Unit) {
  runBlocking { block() }
}

@RunWith(JUnit4::class)
class SignaturesTest {
  @Test
  fun `sign returns signature of correct size`() {
    val privateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)

    val signature = privateKey.sign(certificate, DATA)

    // DER-encoded ECDSA signature using 256-bit key can be 70, 71, or 72 bytes.
    assertThat(signature.size()).isIn(Range.closed(70, 72))
  }

  @Test
  fun `signFlow returns signature of correct size`() = runBlockingTest {
    val privateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)

    val (outFlow, signature) = privateKey.signFlow(certificate, LONG_DATA.asBufferedFlow(24))

    assertThat(outFlow.flatten()).isEqualTo(LONG_DATA)

    // DER-encoded ECDSA signature using 256-bit key can be 70, 71, or 72 bytes.
    assertThat(signature.await().size()).isIn(Range.closed(70, 72))
  }

  @Test
  fun `verifySignature returns true for valid signature`() {
    val privateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)
    val signature = privateKey.sign(certificate, DATA)

    assertTrue(certificate.verifySignature(DATA, signature))
  }

  @Test
  fun `verifySignedFlow returns true for valid signatures`() = runBlockingTest {
    val privateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)
    val regularSig = privateKey.sign(certificate, LONG_DATA)

    val (signFlow, deferredSig) = privateKey.signFlow(certificate, LONG_DATA.asBufferedFlow(24))
    assertThat(signFlow.flatten()).isEqualTo(LONG_DATA)

    val outFlow = certificate.verifySignedFlow(LONG_DATA.asBufferedFlow(24), regularSig)
    val outFlow2 = certificate.verifySignedFlow(LONG_DATA.asBufferedFlow(24), deferredSig.await())
    assertThat(outFlow.flatten()).isEqualTo(LONG_DATA)
    assertThat(outFlow2.flatten()).isEqualTo(LONG_DATA)
  }

  @Test
  fun `verifySignature returns false for signature from different data`() {
    val privateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)
    val signature = privateKey.sign(certificate, DATA)

    assertFalse(certificate.verifySignature(ALT_DATA, signature))
  }

  @Test
  fun `verifySignedFlow throws for invalid signed Flow`() = runBlockingTest {
    val privateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)
    val signature = privateKey.sign(certificate, DATA)

    val outFlow = certificate.verifySignedFlow(LONG_DATA.asBufferedFlow(24), signature)
    assertFailsWith(InvalidSignatureException::class) {
      assertThat(outFlow.flatten()).isEqualTo(LONG_DATA)
    }

    val (signFlow, deferredSig) = privateKey.signFlow(certificate, DATA.asBufferedFlow(24))
    assertThat(signFlow.flatten()).isEqualTo(DATA)

    val outFlow2 = certificate.verifySignedFlow(LONG_DATA.asBufferedFlow(24), deferredSig.await())
    assertFailsWith(InvalidSignatureException::class) { outFlow2.collect() }
  }

  @Test
  fun `verifyExchangeStepSignatures returns false for having only an MC valid signature`() {
    val mcPrivateKey = readPrivateKey(MC_1_KEY_FILE, KEY_ALGORITHM)
    val mcCertificate: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
    val edpCertificate: X509Certificate = readCertificate(EDP_1_CERT_PEM_FILE)

    val mcSignature = mcPrivateKey.sign(mcCertificate, DATA)
    val exchangeWorkflow = ExchangeStep.SignedExchangeWorkflow.newBuilder()
      .apply {
        serializedExchangeWorkflow = DATA
        modelProviderSignature = mcSignature
        dataProviderSignature = randomSignature
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
    val exchangeWorkflow = ExchangeStep.SignedExchangeWorkflow.newBuilder()
      .apply {
        serializedExchangeWorkflow = DATA
        modelProviderSignature = randomSignature
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
    val exchangeWorkflow = ExchangeStep.SignedExchangeWorkflow.newBuilder()
      .apply {
        serializedExchangeWorkflow = DATA
        modelProviderSignature = mcSignature
        dataProviderSignature = edpSignature
      }
      .build()
    assertTrue(verifyExchangeStepSignatures(exchangeWorkflow, mcCertificate, edpCertificate))
  }

  companion object {
    private val random = Random.Default
    private val randomSignature: ByteString = random.nextBytes(70).toByteString()
  }
}
