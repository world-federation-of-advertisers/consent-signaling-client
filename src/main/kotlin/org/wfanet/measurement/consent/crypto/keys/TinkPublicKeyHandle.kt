package org.wfanet.measurement.consent.crypto.keys

import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.PublicKeyVerify
import com.google.protobuf.ByteString
import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey

class TinkPublicKeyHandle internal constructor(private val publicKeysetHandle: KeysetHandle) :
  PublicKeyHandle {
  override fun encrypt(data: ByteString): ByteString {
    val hybridEncrypt: HybridEncrypt = publicKeysetHandle.getPrimitive(HybridEncrypt::class.java)
    val encryptedData = hybridEncrypt.encrypt(data.toByteArray(), byteArrayOf())
    return ByteString.copyFrom(encryptedData)
  }

  override fun verify(signature: ByteString, data: ByteString): Boolean {
    val verifier = publicKeysetHandle.getPrimitive(PublicKeyVerify::class.java)
    try {
      verifier.verify(signature.toByteArray(), data.toByteArray())
    } catch (e: GeneralSecurityException) {
      return false
    }
    return true
  }

  override suspend fun getEncryptionPublicKey(): EncryptionPublicKey {
    val publicKeyByteArrayOutputStream = ByteArrayOutputStream()
    CleartextKeysetHandle.write(
      publicKeysetHandle,
      BinaryKeysetWriter.withOutputStream(publicKeyByteArrayOutputStream)
    )
    return EncryptionPublicKey.newBuilder()
      .apply {
        format = EncryptionPublicKey.Format.TINK_KEYSET
        data = ByteString.copyFrom(publicKeyByteArrayOutputStream.toByteArray())
      }
      .build()
  }
}
