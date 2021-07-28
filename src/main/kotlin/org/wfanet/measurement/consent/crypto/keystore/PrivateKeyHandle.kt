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
package org.wfanet.measurement.consent.crypto.keystore

import com.google.crypto.tink.KeysetHandle
import com.google.protobuf.ByteString
import java.security.PrivateKey
import java.security.cert.X509Certificate
import org.wfanet.measurement.common.crypto.readPrivateKey

/**
 * Clients should only know a handle to a private key, not the actual contents of the private key.
 * Therefore, only this library should read the bytes of the private key.
 */
class PrivateKeyHandle constructor(val id: String, private val keyStore: KeyStore) {

  /**
   * Converts the [PrivateKeyHandle] into a usable [TinkKeysetHandle] object (used by TinkCrypto)
   */
  internal suspend fun toTinkKeysetHandle(): KeysetHandle {
    TODO("Not yet implemented")
  }

  /**
   * Converts a [PrivateKeyHandle] into a Java Security Private Key object. TODO update this so we
   * don't need to expose toJavaPrivateKey to encryption/signing libraries
   */
  suspend fun toJavaPrivateKey(certificate: X509Certificate): PrivateKey? {
    val internalPrivateKey = toByteString()
    internalPrivateKey?.let {
      return readPrivateKey(internalPrivateKey, certificate.getPublicKey().getAlgorithm())
    }
    return null
  }

  /** Returns [ByteString] of the private key */
  internal suspend fun toByteString(): ByteString? {
    return keyStore.readPrivateKey(this)
  }
}
