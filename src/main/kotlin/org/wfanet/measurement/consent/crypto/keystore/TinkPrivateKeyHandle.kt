package org.wfanet.measurement.consent.crypto.keystore

import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.PublicKeySign
import com.google.protobuf.ByteString

class TinkPrivateKeyHandle
internal constructor(val id: String, private val aeadPrivateKeyStore: AeadPrivateKeyStore) : PrivateKeyHandle {
  override suspend fun decrypt(encryptedData: ByteString): ByteString {
    val keysetHandle = aeadPrivateKeyStore.getKeysetHandle(id)
    val hybridDecrypt = keysetHandle.getPrimitive(HybridDecrypt::class.java)
    val decryptedData = hybridDecrypt.decrypt(encryptedData.toByteArray(), byteArrayOf())
    return ByteString.copyFrom(decryptedData)
  }

  override suspend fun getPublicKeyHandle(): PublicKeyHandle {
    val keysetHandle = aeadPrivateKeyStore.getKeysetHandle(id)
    return TinkPublicKeyHandle(keysetHandle.publicKeysetHandle)
  }

  override suspend fun sign(data: ByteString): ByteString {
    val keysetHandle = aeadPrivateKeyStore.getKeysetHandle(id)
    val publicKeySign = keysetHandle.getPrimitive(PublicKeySign::class.java)
    return ByteString.copyFrom(publicKeySign.sign(data.toByteArray()))
  }
}
