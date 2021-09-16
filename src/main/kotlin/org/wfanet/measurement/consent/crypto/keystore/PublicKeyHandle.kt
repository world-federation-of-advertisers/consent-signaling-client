package org.wfanet.measurement.consent.crypto.keystore

import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.protobuf.ByteString
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

interface PublicKeyHandle {
  fun encrypt(data: ByteString): ByteString
  fun verify(signature: ByteString, data: ByteString): Boolean
  suspend fun getEncryptionPublicKey(): EncryptionPublicKey

  companion object {
    fun fromEncryptionPublicKey(encryptionPublicKey: EncryptionPublicKey): PublicKeyHandle =
      when (encryptionPublicKey.format) {
        EncryptionPublicKey.Format.TINK_KEYSET ->
          TinkPublicKeyHandle(
            CleartextKeysetHandle.read(
              BinaryKeysetReader.withBytes(encryptionPublicKey.data.toByteArray())
            )
          )
        else -> throw UnsupportedOperationException() // TODO Fix to something better
      }
  }
}
