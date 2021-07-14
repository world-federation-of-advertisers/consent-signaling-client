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

package org.wfanet.consentsignaling.crypto.hybridencryption

import com.google.protobuf.ByteString
import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

/**
 * FakeHybridCryptor is an implementation of HybridCryptor that actually does no crypto. It only
 * reverses the ByteString. This should only be used for bringup, unit testing, or debugging. Do not
 * use in Production.
 */
class FakeHybridCryptor : HybridCryptor {
  private fun reverseByteString(data: ByteString): ByteString {
    return ByteString.copyFrom(data.toByteArray().reversedArray())
  }

  override fun encrypt(recipientPublicKey: EncryptionPublicKey, data: ByteString): ByteString {
    return reverseByteString(data)
  }

  override fun decrypt(privateKeyHandle: PrivateKeyHandle, encryptedData: ByteString): ByteString {
    return reverseByteString(encryptedData)
  }
}
