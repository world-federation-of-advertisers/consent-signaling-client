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

import com.google.common.truth.Truth
import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.BeforeClass
import org.junit.Test
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.HybridCipherSuite
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.crypto.hybridencryption.testing.ReversingHybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.signMessage
import org.wfanet.measurement.consent.crypto.testing.fakeGetHybridCryptorForCipherSuite
import org.wfanet.measurement.consent.crypto.verifySignature
import org.wfanet.measurement.consent.testing.DUCHY_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_KEY_FILE
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE

private val keyStore = InMemoryKeyStore()
private val hybridCryptor = ReversingHybridCryptor()

private val FAKE_MEASUREMENT_SPEC =
  MeasurementSpec.newBuilder()
    .apply { cipherSuite = HybridCipherSuite.getDefaultInstance() }
    .build()

private val FAKE_ENCRYPTION_PUBLIC_KEY =
  EncryptionPublicKey.newBuilder()
    .apply { publicKeyInfo = ByteString.copyFromUtf8("testPublicKey") }
    .build()

val MC_X509: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
const val MC_PRIVATE_KEY_HANDLE_KEY = "mc1"

val EDP_X509: X509Certificate = readCertificate(EDP_1_CERT_PEM_FILE)
const val EDP_PRIVATE_KEY_HANDLE_KEY = "edp1"

val AGG_X509: X509Certificate = readCertificate(DUCHY_AGG_CERT_PEM_FILE)
const val AGG_PRIVATE_KEY_HANDLE_KEY = "agg1"

class MeasurementConsumerClientTest {
  companion object {
    @BeforeClass
    @JvmStatic
    fun setup() {
      runBlocking {
        keyStore.storePrivateKeyDer(
          MC_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(readPrivateKey(MC_1_KEY_FILE, MC_X509.publicKey.algorithm).encoded)
        )
        keyStore.storePrivateKeyDer(
          EDP_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(readPrivateKey(EDP_1_KEY_FILE, EDP_X509.publicKey.algorithm).encoded)
        )
        keyStore.storePrivateKeyDer(
          AGG_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(DUCHY_AGG_KEY_FILE, AGG_X509.publicKey.algorithm).encoded
          )
        )
      }
    }
  }

  @Test
  fun `measurementConsumer sign requisitionSpec`() = runBlocking {
    val aRequisitionSpec =
      RequisitionSpec.newBuilder()
        .apply {
          measurementPublicKey = FAKE_ENCRYPTION_PUBLIC_KEY.toByteString()
          dataProviderListHash = ByteString.copyFromUtf8("testDataProviderListHash")
        }
        .build()
    val privateKeyHandle = keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY)
    requireNotNull(privateKeyHandle)
    val signedResult =
      signRequisitionSpec(
        requisitionSpec = aRequisitionSpec,
        measurementConsumerPrivateKeyHandle = privateKeyHandle,
        measurementConsumerX509 = MC_X509,
      )
    assertTrue(MC_X509.verifySignature(signedResult))
  }

  @Test
  fun `measurementConsumer encrypt requisitionSpec`() = runBlocking {
    val measurementPublicKey = EncryptionPublicKey.getDefaultInstance()
    val aSignedRequisitionSpec =
      SignedData.newBuilder()
        .apply {
          data = ByteString.copyFromUtf8("testRequisitionSpec")
          signature = ByteString.copyFromUtf8("testRequisitionSpecSignature")
        }
        .build()
    val encryptedSignedRequisitionSpec =
      encryptRequisitionSpec(
        signedRequisitionSpec = aSignedRequisitionSpec,
        measurementPublicKey = measurementPublicKey,
        cipherSuite = FAKE_MEASUREMENT_SPEC.cipherSuite,
        hybridEncryptionMapper = ::fakeGetHybridCryptorForCipherSuite
      )

    val privateKeyHandle = keyStore.getPrivateKeyHandle(EDP_PRIVATE_KEY_HANDLE_KEY)
    requireNotNull(privateKeyHandle)
    val decryptedSignedRequisitionSpec =
      SignedData.parseFrom(hybridCryptor.decrypt(privateKeyHandle, encryptedSignedRequisitionSpec))
    Truth.assertThat(decryptedSignedRequisitionSpec).isEqualTo(aSignedRequisitionSpec)
  }

  @Test
  fun `measurementConsumer sign measurementSpec`() = runBlocking {
    val privateKeyHandle = keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY)
    requireNotNull(privateKeyHandle)
    val signedMeasurementSpec =
      signMeasurementSpec(
        measurementSpec = FAKE_MEASUREMENT_SPEC,
        measurementConsumerPrivateKeyHandle = privateKeyHandle,
        measurementConsumerX509 = MC_X509,
      )
    assertTrue(MC_X509.verifySignature(signedMeasurementSpec))
  }

  @Test
  fun `measurementConsumer sign encryptionPublicKey`() = runBlocking {
    val mcEncryptionPublicKey =
      EncryptionPublicKey.newBuilder()
        .apply { publicKeyInfo = ByteString.copyFromUtf8("testMCPublicKey") }
        .build()
    val privateKeyHandle = keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY)
    requireNotNull(privateKeyHandle)
    val signedEncryptionPublicKey =
      signEncryptionPublicKey(
        encryptionPublicKey = mcEncryptionPublicKey,
        privateKeyHandle = privateKeyHandle,
        measurementConsumerX509 = MC_X509,
      )
    assertTrue(MC_X509.verifySignature(signedEncryptionPublicKey))
  }

  @Test
  fun `measurementConsumer verifies result`() = runBlocking {
    val measurementResult =
      Measurement.Result.newBuilder()
        .apply {
          reach = Measurement.Result.Reach.newBuilder().apply { value = 10 }.build()
          frequency =
            Measurement.Result.Frequency.newBuilder()
              .apply { putAllRelativeFrequencyDistribution(mapOf(1L to 1.0, 2L to 2.0, 3L to 3.0)) }
              .build()
        }
        .build()
    val privateKeyHandle = keyStore.getPrivateKeyHandle(AGG_PRIVATE_KEY_HANDLE_KEY)
    requireNotNull(privateKeyHandle)
    val signedResult =
      signMessage<Measurement.Result>(
        message = measurementResult,
        privateKeyHandle = privateKeyHandle,
        certificate = AGG_X509
      )

    assertTrue(
      verifyResult(
        resultSignature = signedResult.signature,
        measurementResult = measurementResult,
        aggregatorCertificate = AGG_X509,
      )
    )
  }

  @Test
  fun `measurementConsumer verifies encryption public key`() = runBlocking {
    val privateKeyHandle = keyStore.getPrivateKeyHandle(EDP_PRIVATE_KEY_HANDLE_KEY)
    requireNotNull(privateKeyHandle)
    val signedEncryptionPublicKey =
      signMessage<EncryptionPublicKey>(
        message = FAKE_ENCRYPTION_PUBLIC_KEY,
        privateKeyHandle = privateKeyHandle,
        certificate = EDP_X509
      )

    assertTrue(
      verifyEncryptionPublicKey(
        encryptionPublicKeySignature = signedEncryptionPublicKey.signature,
        encryptionPublicKey = FAKE_ENCRYPTION_PUBLIC_KEY,
        edpCertificate = EDP_X509,
      )
    )
  }
}
