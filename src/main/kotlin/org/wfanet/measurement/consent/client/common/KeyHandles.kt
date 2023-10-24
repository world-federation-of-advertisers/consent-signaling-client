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

import com.google.protobuf.Any as ProtoAny
import com.google.protobuf.ByteString
import com.google.protobuf.Message
import com.google.protobuf.any
import com.google.protobuf.kotlin.unpack
import java.security.GeneralSecurityException
import org.wfanet.measurement.api.v2alpha.EncryptedMessage
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.encryptedMessage
import org.wfanet.measurement.api.v2alpha.encryptionPublicKey
import org.wfanet.measurement.common.crypto.PrivateKeyHandle
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

/**
 * Encrypts the [value][ProtoAny.getValue] of [anyMessage].
 *
 * @throws GeneralSecurityException if encryption fails
 */
@Throws(GeneralSecurityException::class)
fun PublicKeyHandle.encryptMessage(
  anyMessage: ProtoAny,
  contextInfo: ByteString? = null
): EncryptedMessage {
  return encryptedMessage {
    ciphertext = hybridEncrypt(anyMessage.value, contextInfo)
    typeUrl = anyMessage.typeUrl
  }
}

/**
 * Decrypts the [ciphertext][EncryptedMessage.getCiphertext] of [encryptedMessage].
 *
 * @throws GeneralSecurityException if decryption fails
 * @throws com.google.protobuf.InvalidProtocolBufferException if [encryptedMessage] does not contain
 *   a message of type [T]
 */
inline fun <reified T : Message> PrivateKeyHandle.decryptMessage(
  encryptedMessage: EncryptedMessage,
  contextInfo: ByteString? = null
): T {
  val plaintext: ByteString = hybridDecrypt(encryptedMessage.ciphertext, contextInfo)
  return any {
      value = plaintext
      typeUrl = encryptedMessage.typeUrl
    }
    .unpack()
}
