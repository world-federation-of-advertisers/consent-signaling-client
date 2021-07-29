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

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Base64
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.HybridCipherSuite
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.common.crypto.testing.FIXED_SERVER_CERT_PEM_FILE as EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.crypto.hashSha256
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridEncryptionMapper
import org.wfanet.measurement.consent.crypto.hybridencryption.testing.ReversingHybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.verifySignature
import org.wfanet.measurement.consent.testing.DUCHY_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE

// TODO Switch this to real cryptography
private val SOME_DATA_PROVIDER_LIST_SALT = ByteString.copyFromUtf8("some-salt-0")
private val SOME_SERIALIZED_DATA_PROVIDER_LIST = ByteString.copyFromUtf8("some-data-provider-list")
private val MC_X509: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
private val DATA_PROVIDER_PUBLIC_KEY =
  EncryptionPublicKey.newBuilder()
    .apply { publicKeyInfo = ByteString.copyFromUtf8("some-public-key") }
    .build()
/** We use a fixed certificate so we can verify the signature against a known certificate. */
private val DATA_PROVIDER_X509: X509Certificate = readCertificate(EDP_1_CERT_PEM_FILE)
private val SOME_REQUISITION_SPEC =
  RequisitionSpec.newBuilder()
    .apply {
      dataProviderListHash =
        hashSha256(ByteString.copyFromUtf8("some-data-provider-list"), SOME_DATA_PROVIDER_LIST_SALT)
    }
    .build()
    .toByteString()
private val SOME_SERIALIZED_MEASUREMENT_SPEC =
  ByteString.copyFromUtf8("some-serialized-measurement-spec")
/** This is pre-calculated using a fixed certificate from common-jvm. */
val DATA_PROVIDER_SIGNATURE =
  ByteString.copyFrom(
    Base64.getDecoder()
      .decode(
        "MEQCIHs37Y61C0kPM/BiiPTU5+rDLG6NpInfQ5OZ+EG1GHUDAiAnplieJkMve3gVvRHY65cQ1vD3" +
          "ZO2bZiiPR4LSqTPFkQ=="
      )
  )

class DuchyClientTest {

  @Test
  fun `duchy verifies edp participation signature`() = runBlocking {
    /** Pre-computing values passed to duchy from kingdom */
    val hybridCryptor: HybridCryptor = ReversingHybridCryptor()
    val someEncryptedRequisitionSpec =
      hybridCryptor.encrypt(DATA_PROVIDER_PUBLIC_KEY, SOME_REQUISITION_SPEC)
    // There is no salt when hashing the encrypted requisition spec
    val someRequisitionSpecHash = hashSha256(someEncryptedRequisitionSpec)

    /** Items already known to the duchy */
    val computation =
      Computation(
        dataProviderList = SOME_SERIALIZED_DATA_PROVIDER_LIST,
        dataProviderListSalt = SOME_DATA_PROVIDER_LIST_SALT,
        measurementSpec = SOME_SERIALIZED_MEASUREMENT_SPEC,
      )
    val requisition =
      Requisition(
        dataProviderCertificate = DATA_PROVIDER_X509,
        requisitionSpecHash = someRequisitionSpecHash
      )

    assertTrue(
      verifyDataProviderParticipation(
        dataProviderParticipationSignature = DATA_PROVIDER_SIGNATURE,
        computation = computation,
        requisition = requisition
      )
    )
  }

  @Test
  fun `duchy sign result`() = runBlocking {
    val keyStore = InMemoryKeyStore()
    val aggregatorX509: X509Certificate = readCertificate(DUCHY_AGG_CERT_PEM_FILE)
    val someMeasurementResult = ByteString.copyFromUtf8("some-measurement-result")
    val aggregatorPrivateKeyHandleKey = "some arbitrary key"
    val aggregatorPrivateKey: PrivateKey =
      readPrivateKey(DUCHY_AGG_KEY_FILE, aggregatorX509.getPublicKey().algorithm)
    val aggregatorPrivateKeyHandle =
      keyStore.storePrivateKeyDer(
        aggregatorPrivateKeyHandleKey,
        ByteString.copyFrom(aggregatorPrivateKey.getEncoded())
      )
    val signedResult =
      signResult(
        measurementResult = someMeasurementResult,
        aggregatorKeyHandle = aggregatorPrivateKeyHandle,
        aggregatorCertificate = aggregatorX509,
      )
    assertTrue(aggregatorX509.verifySignature(signedResult))
  }
}

@Test
fun `duchy encrypt result`() = runBlocking {
  val mockHybridEncryptionMapper: HybridEncryptionMapper = mock()
  val reversingHybridCryptor = ReversingHybridCryptor()
  whenever(mockHybridEncryptionMapper.getHybridCryptorForCipherSuite(any()))
    .thenReturn(reversingHybridCryptor)
  val keyStore = InMemoryKeyStore()
  val measurementPublicKey = EncryptionPublicKey.getDefaultInstance()
  val someSignedMeasurementResult =
    SignedData.newBuilder()
      .apply {
        data = ByteString.copyFromUtf8("some measurement result")
        signature = ByteString.copyFromUtf8("some measurement result signature")
      }
      .build()
  val aggregatorPrivateKeyHandleKey = "some arbitrary key"
  val aggregatorX509: X509Certificate = readCertificate(DUCHY_AGG_CERT_PEM_FILE)
  val aggregatorPrivateKey: PrivateKey =
    readPrivateKey(DUCHY_AGG_KEY_FILE, aggregatorX509.getPublicKey().algorithm)
  val aggregatorPrivateKeyHandle =
    keyStore.storePrivateKeyDer(
      aggregatorPrivateKeyHandleKey,
      ByteString.copyFrom(aggregatorPrivateKey.getEncoded())
    )
  val measurementSpec =
    MeasurementSpec.newBuilder()
      .apply { cipherSuite = HybridCipherSuite.getDefaultInstance() }
      .build()

  val encryptedSignedResult =
    encryptResult(
      cipherSuite = measurementSpec.cipherSuite,
      hybridEncryptionMapper = mockHybridEncryptionMapper,
      signedResult = someSignedMeasurementResult,
      measurementPublicKey = measurementPublicKey
    )
  val decryptedSignedResult =
    SignedData.parseFrom(
      reversingHybridCryptor.decrypt(aggregatorPrivateKeyHandle, encryptedSignedResult)
    )
  assertThat(decryptedSignedResult).isEqualTo(someSignedMeasurementResult)
}
