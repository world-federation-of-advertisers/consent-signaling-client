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

package org.wfanet.measurement.consent.crypto.keystore.testing

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.PrivateKey
import java.security.cert.X509Certificate
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.crypto.keystore.KeyStore
import org.wfanet.measurement.consent.testing.KEY_ALGORITHM
import org.wfanet.measurement.consent.testing.SERVER_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.SERVER_KEY_FILE

private const val KEY = "some arbitrary key"
private val VALUE = ByteString.copyFromUtf8("some arbitrary value")

abstract class AbstractKeyStoreTest {
  abstract val keyStore: KeyStore

  @Test
  fun `write key and read privateKeyHandle to KeyStore`() =
    runBlocking<Unit> {
      val privateKeyHandle1 = keyStore.storePrivateKeyDer(KEY, VALUE)
      val privateKeyHandle2 = keyStore.getPrivateKeyHandle(KEY)
      assertThat(privateKeyHandle1.equals(privateKeyHandle2))
    }

  @Test
  fun `get null for invalid key from KeyStore`() = runBlocking {
    val privateKeyHandle = keyStore.getPrivateKeyHandle(KEY)
    assertThat(privateKeyHandle).isEqualTo(null)
  }

  @Test
  fun `store and retrieve java security PrivateKey`() = runBlocking {
    val privateKey: PrivateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    keyStore.storePrivateKeyDer(KEY, ByteString.copyFrom(privateKey.getEncoded()))
    val privateKeyHandle = requireNotNull(keyStore.getPrivateKeyHandle(KEY))
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)
    assertThat(requireNotNull(privateKeyHandle.toJavaPrivateKey(certificate)).getEncoded())
      .isEqualTo(privateKey.getEncoded())
  }
}
