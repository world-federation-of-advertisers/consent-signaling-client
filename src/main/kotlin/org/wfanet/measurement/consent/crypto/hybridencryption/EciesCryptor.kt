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

import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.PemKeyType
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.protobuf.ByteString
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.consent.crypto.KeyParty
import org.wfanet.measurement.consent.crypto.TinkDerKeysetReader
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle

/**
 * [EciesCryptor] in an implementation of [HybridCryptor] that uses ICIES (Tink)
 * https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
 */
class EciesCryptor : HybridCryptor {
  init {
    HybridConfig.register()
  }

  override fun encrypt(recipientPublicKey: EncryptionPublicKey, data: ByteString): ByteString {
    require(recipientPublicKey.type == EncryptionPublicKey.Type.EC_P256) {
      "Only EC_P256 is currently supported"
    }
    val publicKeySetHandle =
      CleartextKeysetHandle.read(
        TinkDerKeysetReader(
          KeyParty.PUBLIC,
          recipientPublicKey.publicKeyInfo,
          PemKeyType.ECDSA_P256_SHA256
        )
      )
    val hybridEncrypt: HybridEncrypt = publicKeySetHandle.getPrimitive(HybridEncrypt::class.java)
    val encryptedData =
      hybridEncrypt.encrypt(
        data.toByteArray(),
        "".toByteArray() // KEJ - Should we pass in a context to be more secure?
      )
    return ByteString.copyFrom(encryptedData)
  }

  override suspend fun decrypt(
    privateKeyHandle: PrivateKeyHandle,
    encryptedData: ByteString
  ): ByteString {
    val hybridDecrypt: HybridDecrypt =
      privateKeyHandle.toTinkKeysetHandle().getPrimitive(HybridDecrypt::class.java)
    val decryptedData =
      hybridDecrypt.decrypt(
        encryptedData.toByteArray(),
        "".toByteArray() // KEJ - Should we pass in a context to be more secure?
      )
    return ByteString.copyFrom(decryptedData)
  }
}
