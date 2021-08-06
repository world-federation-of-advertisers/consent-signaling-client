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

import com.google.protobuf.ByteString
import java.security.PrivateKey
import java.security.cert.X509Certificate
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.verifySignature
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE

class MeasurementConsumerClientTest {
  @Test
  fun `measurementConsumer sign requisitionSpec`() = runBlocking {
    val keyStore = InMemoryKeyStore()
    val measurementX509: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
    val aRequisitionSpec =
      RequisitionSpec.newBuilder()
        .apply {
          measurementPublicKey = EncryptionPublicKey.newBuilder().apply { publicKeyInfo = ByteString.copyFromUtf8("testPublicKey") }.build().toByteString()
          dataProviderListHash = ByteString.copyFromUtf8("fooDataProviderListHash")
        }
        .build()
    val mcPrivateKeyHandleKey = "mc key"
    val mcPrivateKey: PrivateKey =
      readPrivateKey(MC_1_KEY_FILE, measurementX509.publicKey.algorithm)
    val mcPrivateKeyHandle =
      keyStore.storePrivateKeyDer(
        mcPrivateKeyHandleKey,
        ByteString.copyFrom(mcPrivateKey.encoded)
      )
    val signedResult =
      signRequisitionSpec(
        requisitionSpec = aRequisitionSpec,
        measurementConsumerPrivateKeyHandle = mcPrivateKeyHandle,
        measurementConsumerX509 = ByteString.readFrom(MC_1_CERT_PEM_FILE.inputStream()),
      )
    assertTrue(measurementX509.verifySignature(signedResult))
  }
}
