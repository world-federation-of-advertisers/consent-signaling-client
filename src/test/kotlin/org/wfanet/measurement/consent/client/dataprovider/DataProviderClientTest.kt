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
import kotlin.test.assertTrue
import org.junit.Test
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.crypto.hash
import org.wfanet.measurement.consent.crypto.hybridencryption.FakeHybridCryptor
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keys.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.verifySignature
import org.wfanet.measurement.consent.testing.EDP1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP1_KEY_FILE
import org.wfanet.measurement.consent.testing.KEY_ALGORITHM

class DataProviderClientTest {
  val hybridCryptor: HybridCryptor = FakeHybridCryptor()
  val publicKey = EncryptionPublicKey.getDefaultInstance()
  val dataProviderX509: X509Certificate = readCertificate(EDP1_CERT_PEM_FILE)
  val dataProviderPrivateKey: PrivateKey = readPrivateKey(EDP1_KEY_FILE, KEY_ALGORITHM)
  val someDataProviderListSalt = ByteString.copyFromUtf8("some-salt-0")
  val someRequisitionSpec =
    RequisitionSpec.newBuilder()
      .also {
        it.dataProviderListHash =
          hash(ByteString.copyFromUtf8("some-data-provider-list"), someDataProviderListSalt)
      }
      .build()
      .toByteString()
  val someEncryptedRequisitionSpec = hybridCryptor.encrypt(publicKey, someRequisitionSpec)
  val someSerializedMeasurmentSpec = ByteString.copyFromUtf8("some-serialized-measurement-spec")
  val keyStore = InMemoryKeyStore()
  val privateKeyHandleKey = "some arbitrary key"
  val privateKeyHandle =
    keyStore.storePrivateKeyDer(
      privateKeyHandleKey,
      ByteString.copyFrom(dataProviderPrivateKey.getEncoded())
    )

  @Test
  fun `data provider indicate requisition participation`() {
    val requisition =
      Requisition.newBuilder()
        .also {
          it.encryptedRequisitionSpec = someEncryptedRequisitionSpec
          it.measurementSpec =
            SignedData.newBuilder().also { it.data = someSerializedMeasurmentSpec }.build()
        }
        .build()
    val dataProviderParticipation: SignedData =
      indicateRequisitionParticipation(
        hybridCryptor = hybridCryptor,
        requisition = requisition,
        privateKeyHandle = privateKeyHandle,
        dataProviderListSalt = someDataProviderListSalt,
        dataProviderX509 = ByteString.copyFrom(dataProviderX509.getEncoded())
      )
    assertThat(dataProviderParticipation.data.toByteArray().joinToString())
      .isEqualTo(
        "5, 0, 64, 63, 17, 14, 102, -93, -34, -104, 89, 117, -96, -106, 23, 101, 2, -95, 43, 106, 14, -100, 32, 21, -9, 123, -101, -4, 38, -87, 85, -101, 82, 79, 20, 13, -75, -80, 42, -5, -72, -109, -115, -52, 64, 70, -84, 57, -102, 7, 68, 94, -33, -83, 28, -118, -125, 22, -110, -50, 98, 90, -93, -60, 115, 111, 109, 101, 45, 115, 101, 114, 105, 97, 108, 105, 122, 101, 100, 45, 109, 101, 97, 115, 117, 114, 101, 109, 101, 110, 116, 45, 115, 112, 101, 99"
      )
    assertTrue(dataProviderX509.verifySignature(dataProviderParticipation))
  }
}
