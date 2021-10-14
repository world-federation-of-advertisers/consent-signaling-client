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

import com.google.protobuf.ByteString
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle

/**
 * Does no crypto.
 *
 * This encrypts and decrypts by reversing the input plaintext or ciphertext.
 *
 * This should only be used for bring-up, unit testing, or debugging. Do not use in production.
 */
class ReversingHybridCryptor : HybridCryptor {
  private fun reverseByteString(data: ByteString): ByteString {
    return ByteString.copyFrom(data.toByteArray().reversedArray())
  }

  override fun encrypt(recipientPublicKey: EncryptionPublicKey, data: ByteString): ByteString {
    return reverseByteString(data)
  }

  override suspend fun decrypt(
    privateKeyHandle: PrivateKeyHandle,
    encryptedData: ByteString
  ): ByteString {
    return reverseByteString(encryptedData)
  }
}
