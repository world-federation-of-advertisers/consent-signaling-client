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
package org.wfanet.measurement.consent.crypto.keys

import com.google.protobuf.ByteString

/**
 * Clients should only know a handle to a private key, not the actual contents of the private key.
 * Therefore, only this library should read the bytes of the private key.
 */
interface PrivateKeyHandle {
  fun getId(): String
  suspend fun decrypt(encryptedBytes: ByteString): ByteString
  suspend fun getPublicKeyHandle(): PublicKeyHandle
  suspend fun sign(data: ByteString): ByteString
}
