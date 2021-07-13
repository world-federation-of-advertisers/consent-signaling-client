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

package org.wfanet.consentsignaling.crypto.keys.testing

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import kotlin.test.assertFailsWith
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.wfanet.consentsignaling.crypto.keys.KeyStore
import org.wfanet.consentsignaling.crypto.keys.KeyStore.KeyNotFoundException

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
  fun `get error for invalid key from KeyStore`() =
    runBlocking<Unit> {
      assertFailsWith<KeyNotFoundException> { keyStore.getPrivateKeyHandle(KEY) }
    }

  @Test
  fun `get false for invalid key from KeyStore`() = runBlocking {
    val isFound = keyStore.isFound(KEY)
    assertThat(isFound).isEqualTo(false)
  }

  @Test
  fun `get true for valid key from KeyStore`() = runBlocking {
    keyStore.storePrivateKeyDer(KEY, VALUE)
    val isFound = keyStore.isFound(KEY)
    assertThat(isFound).isEqualTo(true)
  }
}
