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
import kotlin.test.assertFailsWith
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.common.crypto.testing.FIXED_SERVER_CERT_PEM_FILE as SERVER_CERT_PEM_FILE
import org.wfanet.measurement.common.crypto.testing.FIXED_SERVER_KEY_FILE as SERVER_KEY_FILE
import org.wfanet.measurement.common.crypto.testing.KEY_ALGORITHM
import org.wfanet.measurement.consent.crypto.keystore.KeyStore

private const val KEY = "some arbitrary key"
private val VALUE = ByteString.copyFromUtf8("some arbitrary value")
private val OTHER_VALUE = ByteString.copyFromUtf8("some other arbitrary value")

abstract class AbstractKeyStoreTest {
  abstract val keyStore: KeyStore

  @Test
  fun `getPrivateKeyHandle returns handle for existing key`() = runBlocking {
    val privateKeyHandle1 = keyStore.storePrivateKeyDer(KEY, VALUE)
    val privateKeyHandle2 = keyStore.getPrivateKeyHandle(KEY)

    assertThat(privateKeyHandle2).isNotNull()
    assertThat(privateKeyHandle1.id).isEqualTo(privateKeyHandle2?.id)
  }

  @Test
  fun `storePrivateKeyDer returns error for existing key`() =
    runBlocking<Unit> {
      keyStore.storePrivateKeyDer(KEY, VALUE)
      assertFailsWith(IllegalArgumentException::class) {
        keyStore.storePrivateKeyDer(KEY, OTHER_VALUE)
      }
    }

  @Test
  fun `getPrivateKeyHandle returns null when key is not found`() = runBlocking {
    val privateKeyHandle = keyStore.getPrivateKeyHandle(KEY)
    assertThat(privateKeyHandle).isNull()
  }

  @Test
  fun `toJavaPrivateKey returns existing private key`() = runBlocking {
    val privateKey: PrivateKey = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM)
    keyStore.storePrivateKeyDer(KEY, ByteString.copyFrom(privateKey.encoded))
    val privateKeyHandle = requireNotNull(keyStore.getPrivateKeyHandle(KEY))
    val certificate: X509Certificate = readCertificate(SERVER_CERT_PEM_FILE)
    assertThat(requireNotNull(privateKeyHandle.toJavaPrivateKey(certificate)).encoded)
      .isEqualTo(privateKey.encoded)
  }
}
