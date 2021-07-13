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
 * KeyStore is an abstract class for storing private keys in different implementation of KMS
 *
 * Clients of this class can store PrivateKeys (currently in DER format) and can retrieve a
 * PrivateKeyHandle of the stored key, however the client will not be enable to read the actual key
 * contents stored in KMS. Only this 'crypto' module will have access to the actual private key
 * contents (currently used by signage and crypto classes)
 */
abstract class KeyStore {
  class KeyNotFoundException(id: String) : Exception("Private key $id was not found")

  /** Store the private key in KeyStorage and returns a PrivateKeyHandle */
  abstract fun storePrivateKeyDER(id: String, privateKeyBytes: ByteString): PrivateKeyHandle

  /** Retrieves a PrivateKeyHandle of an existing key in KeyStore */
  abstract fun getPrivateKeyHandle(id: String): PrivateKeyHandle

  /**
   * Reads the contents of a private key stored in KeyStore. This can only be access by this
   * 'crypto' module
   */
  internal abstract fun readPrivateKey(privateKeyHandle: PrivateKeyHandle): ByteString
}
