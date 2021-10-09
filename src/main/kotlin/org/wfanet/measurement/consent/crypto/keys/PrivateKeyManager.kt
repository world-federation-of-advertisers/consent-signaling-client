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

/**
 * [KeyStore] is an abstract class for storing private keys in different implementation of KMS
 *
 * Clients of this class can store [PrivateKeyBytes] (currently in DER format) and can retrieve a
 * [PrivateKeyHandle] of the stored key, however the client will not be enable to read the actual
 * key contents stored in KMS.
 */
interface PrivateKeyManager {

  /**
   * Stores the [privateKeyBytes] at [id]
   *
   * @return [PrivateKeyHandle] representing the private key
   */
  suspend fun generatePrivateKey(name: String): PrivateKeyHandle

  /**
   * Accesses an existing private key handle specified by [id].
   *
   * @return [PrivateKeyHandle] for the key or `null` if not found.
   */
  suspend fun getPrivateKey(id: String): PrivateKeyHandle?
}
