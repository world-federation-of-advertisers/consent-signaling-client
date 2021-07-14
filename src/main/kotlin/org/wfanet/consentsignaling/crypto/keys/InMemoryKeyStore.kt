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

package org.wfanet.consentsignaling.crypto.keys

import com.google.protobuf.ByteString

/**
 * A simple "In-Memory" implementation of [KeyStore] using a [HashMap]
 *
 * This is for bring-up and unit testing only. This is not secure and should not be used in
 * production.
 */
class InMemoryKeyStore : KeyStore() {
  private val keyStoreMap = HashMap<String, ByteString>()

  override fun storePrivateKeyDer(id: String, privateKeyBytes: ByteString): PrivateKeyHandle {
    keyStoreMap[id] = privateKeyBytes
    return PrivateKeyHandle(id, this)
  }

  override fun getPrivateKeyHandle(id: String): PrivateKeyHandle {
    keyStoreMap[id]?.let {
      return PrivateKeyHandle(id, this)
    }
    throw KeyStore.KeyNotFoundException(id)
  }

  override fun isFound(id: String): Boolean {
    keyStoreMap[id]?.let {
      return true
    }
    return false
  }

  override fun isFound(privateKeyHandle: PrivateKeyHandle): Boolean {
    keyStoreMap[privateKeyHandle.id]?.let {
      return true
    }
    return false
  }

  override fun readPrivateKey(privateKeyHandle: PrivateKeyHandle): ByteString {
    keyStoreMap[privateKeyHandle.id]?.let {
      return it
    }
    throw KeyStore.KeyNotFoundException(privateKeyHandle.id)
  }
}
