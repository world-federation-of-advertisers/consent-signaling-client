package org.wfanet.measurement.consent.crypto.keys

import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.protobuf.ByteString
import java.io.ByteArrayOutputStream
import java.util.UUID
import org.wfanet.measurement.common.crypto.Aead
import org.wfanet.measurement.common.flatten
import org.wfanet.measurement.storage.StorageClient
import org.wfanet.measurement.storage.Store

private const val BLOB_KEY_PREFIX = "/private-keys"

/** Private Key Creation and Storage using Aead + Store */
class TinkPrivateKeyManager(private val aead: Aead, val storageClient: StorageClient) :
  PrivateKeyManager {
  private val privateKeyStore =
    object : Store<PrivateKeyBlobContext>(storageClient, ::generateBlobKey) {
      override val blobKeyPrefix = BLOB_KEY_PREFIX
    }

  /**
   * Wrap CMM Aead to support the tink.Aead interface required by Tink
   */
  private val tinkAead = object : com.google.crypto.tink.Aead {
    override fun encrypt(plaintext: ByteArray?, associatedData: ByteArray?): ByteArray {
      return aead.encrypt(ByteString.copyFrom(plaintext)).toByteArray()
    }

    override fun decrypt(ciphertext: ByteArray?, associatedData: ByteArray?): ByteArray {
      return aead.decrypt(ByteString.copyFrom(ciphertext)).toByteArray()
    }
  }

  override suspend fun generatePrivateKey(
    name: String,
  ): PrivateKeyHandle {
    val privateKeysetHandle =
      KeysetHandle.generateNew(KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"))
    val privateKeyByteArrayOutputStream = ByteArrayOutputStream()
    privateKeysetHandle.write(
      BinaryKeysetWriter.withOutputStream(privateKeyByteArrayOutputStream),
      tinkAead
    )
    val privateKeyBlob =
      privateKeyStore.write(
        PrivateKeyBlobContext(name),
        ByteString.copyFrom(privateKeyByteArrayOutputStream.toByteArray())
      )
    return TinkPrivateKeyHandle(privateKeyBlob.blobKey, this)
  }

  override suspend fun getPrivateKey(id: String): PrivateKeyHandle {
    return TinkPrivateKeyHandle(id, this)
  }

  internal suspend fun getKeysetHandle(id: String): KeysetHandle {
    val privateKeyBlob = privateKeyStore.get(id)
    val privateKeyBytes =
      checkNotNull(privateKeyBlob).read(privateKeyBlob.storageClient.defaultBufferSizeBytes)
    return KeysetHandle.read(
      BinaryKeysetReader.withBytes(privateKeyBytes.flatten().toByteArray()),
      tinkAead
    )
  }
}

/** The context used to generate blob key for the [AeadPrivateKeyStore]. */
data class PrivateKeyBlobContext(
  val privateKeyName: String,
)

/** Generates a Blob key using the [PrivateKeyBlobContext]. */
private fun generateBlobKey(context: PrivateKeyBlobContext): String {
  return "/${context.privateKeyName}/${UUID.randomUUID()}"
}
