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

package org.wfanet.measurement.consent.client.kingdom

import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.signMessage
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE

private val MEASUREMENT_PUBLIC_KEY =
  EncryptionPublicKey.newBuilder()
    .apply { data = ByteString.copyFromUtf8("some-public-key") }
    .build()

private val keyStore = InMemoryKeyStore()

private val FAKE_MEASUREMENT_SPEC =
  MeasurementSpec.newBuilder()
    .apply { measurementPublicKey = MEASUREMENT_PUBLIC_KEY.toByteString() }
    .build()

private val MC_CERTIFICATE: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
private const val MC_PRIVATE_KEY_HANDLE_KEY = "mc1"

@RunWith(JUnit4::class)
class KingdomClientTest {
  companion object {
    @BeforeClass
    @JvmStatic
    fun initializePrivateKeyKeystore() {
      runBlocking {
        keyStore.storePrivateKeyDer(
          MC_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(MC_1_KEY_FILE, MC_CERTIFICATE.publicKey.algorithm).encoded
          )
        )
      }
    }
  }

  @Test
  fun `verifyMeasurementSpec verifies valid MeasurementSpec signature`() = runBlocking {
    val privateKeyHandle = keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(privateKeyHandle)
    val signedMeasurementSpec =
      signMessage<MeasurementSpec>(
        message = FAKE_MEASUREMENT_SPEC,
        privateKeyHandle = privateKeyHandle,
        certificate = MC_CERTIFICATE
      )

    assertTrue(
      verifyMeasurementSpec(
        measurementSpecSignature = signedMeasurementSpec.signature,
        measurementSpec = FAKE_MEASUREMENT_SPEC,
        measurementConsumerCertificate = MC_CERTIFICATE,
      )
    )
  }
}
