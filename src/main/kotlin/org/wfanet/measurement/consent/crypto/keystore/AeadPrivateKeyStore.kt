package org.wfanet.measurement.consent.crypto.keystore

import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.protobuf.ByteString
import java.io.ByteArrayOutputStream
import org.wfanet.measurement.common.flatten
import org.wfanet.measurement.consent.crypto.AeadBlobContext
import org.wfanet.measurement.consent.crypto.AeadStore

/** Private Key Creation and Storage using AeadStore */
class AeadPrivateKeyStore(private val aeadStore: AeadStore) : PrivateKeyStore {
  override suspend fun generatePrivateKey(
    id: String,
  ): PrivateKeyHandle {
    val privateKeysetHandle =
      KeysetHandle.generateNew(KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"))
    val privateKeyByteArrayOutputStream = ByteArrayOutputStream()
    /**
     * Tink does not provide a way to separate the aead encryption and writing of the key. To
     * workaround this we are using CleartextKeysetHandle which calls the unencrypted write method,
     * however this is only written to local variable of this scope and then is immediately
     * encrypted when writing to AeadStore
     */
    CleartextKeysetHandle.write(
      privateKeysetHandle,
      BinaryKeysetWriter.withOutputStream(privateKeyByteArrayOutputStream)
    )
    aeadStore.write(
      AeadBlobContext(id),
      ByteString.copyFrom(privateKeyByteArrayOutputStream.toByteArray())
    )
    return TinkPrivateKeyHandle(id, this)
  }

  override suspend fun getPrivateKeyHandle(id: String): PrivateKeyHandle {
    return TinkPrivateKeyHandle(id, this)
  }

  internal suspend fun getKeysetHandle(id: String): KeysetHandle {
    val privateKeyBlob = aeadStore.get(id)
    val privateKeyBytes =
      checkNotNull(privateKeyBlob).read(privateKeyBlob.storageClient.defaultBufferSizeBytes)
    /**
     * Tink does not provide a way to separate reading of the key and aead decryption. To workaround
     * this we are using CleartextKeysetHandle which calls the unencrypted read method, however this
     * is read from AeadStore and immediately loaded into a Tink KeysetHandle
     */
    return CleartextKeysetHandle.read(
      BinaryKeysetReader.withBytes(privateKeyBytes.flatten().toByteArray())
    )
  }
}
