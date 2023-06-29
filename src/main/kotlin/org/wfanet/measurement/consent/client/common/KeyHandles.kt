/*
 * Copyright 2021 The Cross-Media Measurement Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wfanet.measurement.consent.client.common

import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.encryptionPublicKey
import org.wfanet.measurement.common.crypto.PublicKeyHandle
import org.wfanet.measurement.common.crypto.tink.TinkPublicKeyHandle

/** Converts this [EncryptionPublicKey] to a [PublicKeyHandle]. */
fun EncryptionPublicKey.toPublicKeyHandle(): PublicKeyHandle {
  @Suppress("WHEN_ENUM_CAN_BE_NULL_IN_JAVA") // protobuf enum fields are never null.
  return when (format) {
    EncryptionPublicKey.Format.TINK_KEYSET -> TinkPublicKeyHandle(data)
    EncryptionPublicKey.Format.FORMAT_UNSPECIFIED,
    EncryptionPublicKey.Format.UNRECOGNIZED -> error("format not specified")
  }
}

/** Serializes this [PublicKeyHandle] to an [EncryptionPublicKey]. */
fun PublicKeyHandle.toEncryptionPublicKey(): EncryptionPublicKey {
  return when (this) {
    is TinkPublicKeyHandle -> toEncryptionPublicKey()
    else -> error("Unhandled PublicKeyHandle type")
  }
}

/** Serializes this [TinkPublicKeyHandle] to an [EncryptionPublicKey]. */
fun TinkPublicKeyHandle.toEncryptionPublicKey() = encryptionPublicKey {
  format = EncryptionPublicKey.Format.TINK_KEYSET
  data = toByteString()
}
