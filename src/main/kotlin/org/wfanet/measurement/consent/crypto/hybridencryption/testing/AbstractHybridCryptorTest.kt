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

package org.wfanet.measurement.consent.crypto.hybridencryption.testing

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.KeyStore
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore

private val PLAINTEXT = ByteString.copyFromUtf8("some-plaintext")
private val PRIVATE_KEY = ByteString.copyFromUtf8("some-private-key")
private const val KEYSTORE_ID = "some-keystore-id"
private val ENCRYPTION_PUBLIC_KEY = EncryptionPublicKey.getDefaultInstance()

abstract class AbstractHybridCryptorTest(val keystore: KeyStore = InMemoryKeyStore()) {
  abstract val hybridCryptor: HybridCryptor

  @Test
  fun `encrypt result should not equal original data`() {
    assertThat(hybridCryptor.encrypt(ENCRYPTION_PUBLIC_KEY, PLAINTEXT)).isNotEqualTo(PLAINTEXT)
  }

  @Test
  fun `encrypt data and then decrypt result should equal original data`() = runBlocking {
    keystore.storePrivateKeyDer(KEYSTORE_ID, PRIVATE_KEY)
    val privateKeyHandle = requireNotNull(keystore.getPrivateKeyHandle(KEYSTORE_ID))
    val encryptedValue = hybridCryptor.encrypt(ENCRYPTION_PUBLIC_KEY, PLAINTEXT)
    val decryptedValue = hybridCryptor.decrypt(privateKeyHandle, encryptedValue)
    assertThat(decryptedValue).isEqualTo(PLAINTEXT)
  }
}