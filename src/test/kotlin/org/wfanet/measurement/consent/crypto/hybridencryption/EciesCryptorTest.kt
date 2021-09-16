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

package org.wfanet.measurement.consent.crypto.hybridencryption

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import kotlinx.coroutines.runBlocking
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE

private val keyStore = InMemoryKeyStore()
private val MC_CERTIFICATE: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
private const val MC_PRIVATE_KEY_HANDLE_KEY = "mc1"

@RunWith(JUnit4::class)
class EciesCryptorTest {

  companion object {
    @BeforeClass
    @JvmStatic
    fun initializePrivateKeyKeystore() {
      runBlocking {
        keyStore.storePrivateKeyDer(
          MC_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(MC_1_KEY_FILE, MC_CERTIFICATE.publicKey.algorithm).encoded
          )
        )
      }
    }
  }

  @Test
  fun `Ecies Cryptor Encrypts and Decrypts Data`() = runBlocking {
    val encryptionPublicKey =
      EncryptionPublicKey.newBuilder()
        .apply {
          publicKeyInfo = ByteString.copyFrom(MC_CERTIFICATE.publicKey.encoded)
          type = EncryptionPublicKey.Type.EC_P256
        }
        .build()

    val eciesCryptor = EciesCryptor()
    val data = ByteString.copyFromUtf8("something exciting to encrypt")

    // Encrypt the Data
    val encryptedData = eciesCryptor.encrypt(encryptionPublicKey, data)
    // data and encrypted data should not be equal
    assertThat(encryptedData).isNotEqualTo(data)

    // Decrypt the Data
    val privateKeyHandle = checkNotNull(keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY))
    val decryptedData = eciesCryptor.decrypt(privateKeyHandle, encryptedData)
    assertThat(decryptedData).isEqualTo(data)
  }
}
