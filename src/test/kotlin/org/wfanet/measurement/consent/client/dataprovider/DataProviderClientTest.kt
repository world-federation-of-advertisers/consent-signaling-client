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

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Base64
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.common.crypto.testing.KEY_ALGORITHM
import org.wfanet.measurement.consent.crypto.hashSha256
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.hybridencryption.testing.ReversingHybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.verifySignature
import org.wfanet.measurement.consent.testing.EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_KEY_FILE

private val PUBLIC_KEY = EncryptionPublicKey.getDefaultInstance()
private val DATA_PROVIDER_X509: X509Certificate = readCertificate(EDP_1_CERT_PEM_FILE)
private val DATA_PROVIDER_PRIVATE_KEY: PrivateKey = readPrivateKey(EDP_1_KEY_FILE, KEY_ALGORITHM)
private val SOME_DATA_PROVIDER_LIST_SALT = ByteString.copyFromUtf8("some-salt-0")
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
private val PRIVATE_KEY_HANDLE = "some arbitrary key"

class DataProviderClientTest {
  val hybridCryptor: HybridCryptor = ReversingHybridCryptor()
  val someEncryptedRequisitionSpec = hybridCryptor.encrypt(PUBLIC_KEY, SOME_REQUISITION_SPEC)
  val keyStore = InMemoryKeyStore()

  @Test
  fun `data provider calculates requisition participation signature`() = runBlocking {
    val privateKeyHandle =
      keyStore.storePrivateKeyDer(
        PRIVATE_KEY_HANDLE,
        ByteString.copyFrom(DATA_PROVIDER_PRIVATE_KEY.getEncoded())
      )
    val requisition =
      Requisition.newBuilder()
        .apply {
          encryptedRequisitionSpec = someEncryptedRequisitionSpec
          measurementSpec =
            SignedData.newBuilder().apply { data = SOME_SERIALIZED_MEASUREMENT_SPEC }.build()
        }
        .build()
    val dataProviderParticipation: SignedData =
      createParticipationSignature(
        hybridCryptor = hybridCryptor,
        requisition = requisition,
        privateKeyHandle = privateKeyHandle,
        dataProviderX509 = DATA_PROVIDER_X509
      )
    assertThat(Base64.getEncoder().encodeToString(dataProviderParticipation.data.toByteArray()))
      .isEqualTo(
        "0FDiZZy02niAX0VmTcjpPbm4iiG/2xLJj2H8StnCF3xSTxQNtbAq+7iTjcxARqw5mgdEXt+tHIqDFpLOYlq" +
          "jxHNvbWUtc2VyaWFsaXplZC1tZWFzdXJlbWVudC1zcGVj"
      )
    assertTrue(DATA_PROVIDER_X509.verifySignature(dataProviderParticipation))
  }
}
