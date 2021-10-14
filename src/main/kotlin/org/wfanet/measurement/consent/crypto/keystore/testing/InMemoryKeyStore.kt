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

import com.google.protobuf.ByteString
import java.util.concurrent.ConcurrentHashMap
import org.wfanet.measurement.consent.crypto.keystore.KeyStore
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle

/**
 * A simple "In-Memory" implementation of [KeyStore] using a [HashMap]
 *
 * This is for bring-up and unit testing only. This is not secure and should not be used in
 * production.
 */
class InMemoryKeyStore : KeyStore() {
  private val keyStoreMap = ConcurrentHashMap<String, ByteString>()

  override suspend fun storePrivateKeyDer(
    id: String,
    privateKeyBytes: ByteString
  ): PrivateKeyHandle {
    require(keyStoreMap.putIfAbsent(id, privateKeyBytes) == null) {
      "Cannot write to an existing key: $id"
    }
    return PrivateKeyHandle(id, this)
  }

  override suspend fun getPrivateKeyHandle(id: String): PrivateKeyHandle? {
    return keyStoreMap[id]?.let { PrivateKeyHandle(id, this) }
  }

  override suspend fun readPrivateKey(privateKeyHandle: PrivateKeyHandle): ByteString? {
    return keyStoreMap[privateKeyHandle.id]
  }
}
