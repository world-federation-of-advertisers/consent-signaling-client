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

package org.wfanet.measurement.consent.crypto.keys.testing

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.wfanet.measurement.consent.crypto.keys.KeyStore

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
}
