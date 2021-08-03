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

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Random
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.HybridCipherSuite
import org.wfanet.measurement.api.v2alpha.Measurement.Result as MeasurementResult
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.crypto.hybridencryption.EciesCryptor
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.testing.DUCHY_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_KEY_FILE

@RunWith(JUnit4::class)
class UtilsTest {

  @Test
  fun `signed message proto has correct data and signature`() = runBlocking {
    val keyStore = InMemoryKeyStore()
    val certificate: X509Certificate = readCertificate(DUCHY_AGG_CERT_PEM_FILE)
    val someMeasurementResult =
      MeasurementResult.newBuilder()
        .apply {
          reach = MeasurementResult.Reach.newBuilder().apply { value = Random().nextLong() }.build()
          frequency = MeasurementResult.Frequency.getDefaultInstance()
        }
        .build()
    val aggregatorPrivateKeyHandleKey = "some arbitrary key"
    val aggregatorPrivateKey: PrivateKey =
      readPrivateKey(DUCHY_AGG_KEY_FILE, certificate.getPublicKey().algorithm)
    val privateKeyHandle =
      keyStore.storePrivateKeyDer(
        aggregatorPrivateKeyHandleKey,
        ByteString.copyFrom(aggregatorPrivateKey.getEncoded())
      )
    val signedMessage =
      signMessage<MeasurementResult>(
        message = someMeasurementResult,
        privateKeyHandle = privateKeyHandle,
        certificate = certificate
      )
    assertThat(signedMessage.data).isEqualTo(someMeasurementResult.toByteString())
    assertTrue(certificate.verifySignature(signedMessage))
  }

  @Test
  fun `supported cipher suite maps to to EciesCryptor`() {
    val cipherSuite =
      HybridCipherSuite.newBuilder()
        .apply {
          kem = HybridCipherSuite.KeyEncapsulationMechanism.ECDH_P256_HKDF_HMAC_SHA256
          dem = HybridCipherSuite.DataEncapsulationMechanism.AES_128_GCM
        }
        .build()
    val hybridCryptor = getHybridCryptorForCipherSuite(cipherSuite)
    assertThat(hybridCryptor).isInstanceOf(EciesCryptor::class.java)
  }

  @Test
  fun `unsupported cipher suite map to hybrid cryptor returns error`() {
    val cipherSuite =
      HybridCipherSuite.newBuilder()
        .apply {
          kem = HybridCipherSuite.KeyEncapsulationMechanism.KEY_ENCAPSULATION_MECHANISM_UNSPECIFIED
          dem =
            HybridCipherSuite.DataEncapsulationMechanism.DATA_ENCAPSULATION_MECHANISM_UNSPECIFIED
        }
        .build()
    assertFailsWith(IllegalArgumentException::class) { getHybridCryptorForCipherSuite(cipherSuite) }
  }
}
