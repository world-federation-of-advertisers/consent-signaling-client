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
import java.nio.file.Paths
import java.security.cert.X509Certificate
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.testing.SERVER_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.SERVER_KEY_FILE
import org.wfanet.measurement.consent.testing.KEY_ALGORITHM

private val DATA = ByteString.copyFromUtf8("I am some data to sign")
private val ALT_DATA = ByteString.copyFromUtf8("I am some alternative data")

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
  fun `verifySignature returns true for valid signature`() {
    val privateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)
    val signature = privateKey.sign(certificate, DATA)

    assertTrue(certificate.verifySignature(DATA, signature))
  }

  @Test
  fun `verifySignature returns false for signature from different data`() {
    val privateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)
    val signature = privateKey.sign(certificate, DATA)

    assertFalse(certificate.verifySignature(ALT_DATA, signature))
  }

}
