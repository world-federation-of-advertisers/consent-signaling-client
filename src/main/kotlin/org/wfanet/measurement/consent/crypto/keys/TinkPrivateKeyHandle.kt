package org.wfanet.measurement.consent.crypto.keys

import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.PublicKeySign
import com.google.protobuf.ByteString

class TinkPrivateKeyHandle
internal constructor(private val id: String, private val tinkPrivateKeyManager: TinkPrivateKeyManager) :
  PrivateKeyHandle {
  override fun getId(): String {
    return id
  }

  override suspend fun decrypt(encryptedData: ByteString): ByteString {
    val keysetHandle = tinkPrivateKeyManager.getKeysetHandle(id)
    val hybridDecrypt = keysetHandle.getPrimitive(HybridDecrypt::class.java)
    val decryptedData = hybridDecrypt.decrypt(encryptedData.toByteArray(), byteArrayOf())
    return ByteString.copyFrom(decryptedData)
  }

  override suspend fun getPublicKeyHandle(): PublicKeyHandle {
    val keysetHandle = tinkPrivateKeyManager.getKeysetHandle(id)
    return TinkPublicKeyHandle(keysetHandle.publicKeysetHandle)
  }

  override suspend fun sign(data: ByteString): ByteString {
    val keysetHandle = tinkPrivateKeyManager.getKeysetHandle(id)
    val publicKeySign = keysetHandle.getPrimitive(PublicKeySign::class.java)
    return ByteString.copyFrom(publicKeySign.sign(data.toByteArray()))
  }
}
