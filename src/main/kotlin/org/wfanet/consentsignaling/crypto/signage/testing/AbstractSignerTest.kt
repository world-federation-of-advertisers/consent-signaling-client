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

package org.wfanet.consentsignaling.crypto.signage.testing

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import kotlinx.coroutines.runBlocking
import org.junit.Before
import org.junit.Test
import org.wfanet.consentsignaling.crypto.keys.InMemoryKeyStore
import org.wfanet.consentsignaling.crypto.keys.KeyStore
import org.wfanet.consentsignaling.crypto.signage.Signer
import org.wfanet.measurement.api.v2alpha.Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

private val PLAINTEXT = ByteString.copyFromUtf8("some-plaintext")
private val KEYSTORE_ADDRESS = "some-keystore-address"
private val ENCRYPTION_PUBLIC_KEY = EncryptionPublicKey.getDefaultInstance()

abstract class AbstractSignerTest(
  val certificate: Certificate,
  val privateKey: ByteString,
  val keystore: KeyStore = InMemoryKeyStore()
) {
  abstract val signer: Signer

  @Before
  open fun beforeEach() {
    keystore.storePrivateKeyDer(KEYSTORE_ADDRESS, privateKey)
  }

  @Test
  fun `sign should not equal input`() = runBlocking {
    val privateKeyHandle = keystore.getPrivateKeyHandle(KEYSTORE_ADDRESS)
    assertThat(signer.sign(certificate, privateKeyHandle, PLAINTEXT)).isNotEqualTo(PLAINTEXT)
  }

  @Test
  fun `sign and then verify should equal true`() = runBlocking {
    val privateKeyHandle = keystore.getPrivateKeyHandle("some-keystore-address")
    val signature = signer.sign(certificate, privateKeyHandle, PLAINTEXT)
    assertThat(signer.verify(certificate, signature, PLAINTEXT)).isEqualTo(true)
  }
}
