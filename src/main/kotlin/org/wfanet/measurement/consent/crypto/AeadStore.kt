package org.wfanet.measurement.consent.crypto

import com.google.protobuf.ByteString
import java.util.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.runBlocking
import org.wfanet.measurement.common.asBufferedFlow
import org.wfanet.measurement.common.flatten
import org.wfanet.measurement.storage.BlobKeyGenerator
import org.wfanet.measurement.storage.StorageClient
import org.wfanet.measurement.storage.Store

/** TODO: This should be moved to common-jvm crytpo */
private const val BLOB_KEY_PREFIX = "/aead"

class AeadStore
private constructor(
  private val aead: Aead,
  private val storageClient: StorageClient,
  generateBlobKey: BlobKeyGenerator<AeadBlobContext>
) : Store<AeadBlobContext>(storageClient, generateBlobKey) {
  constructor(
    aead: Aead,
    storageClient: StorageClient
  ) : this(aead, storageClient, ::generateBlobKey)

  override val blobKeyPrefix = BLOB_KEY_PREFIX

  /** TODO Need to make Store.write "open" */
  override suspend fun write(context: AeadBlobContext, content: Flow<ByteString>): Blob {
    return write(context, content.flatten())
  }

  /** TODO Need to make Store.write "open" */
  override suspend fun write(context: AeadBlobContext, content: ByteString): Blob {
    val encryptedContent = aead.encrypt(content)
    return super.write(context, encryptedContent)
  }

  /** TODO Need to make Store.get "open" */
  override fun get(blobKey: String): Blob? {
    val blob = super.get(blobKey)
    return blob?.let { Blob(blobKey, AeadBlob(it)) }
  }

  private inner class AeadBlob(val blob: Blob) : StorageClient.Blob {
    override val size: Long = readEncyptedBytes().size().toLong()

    override val storageClient = this@AeadStore.storageClient

    override fun read(bufferSizeBytes: Int): Flow<ByteString> {
      return this@AeadStore.aead
        .decrypt(readEncyptedBytes())
        .asBufferedFlow(storageClient.defaultBufferSizeBytes)
    }

    override fun delete() = blob.delete()

    private fun readEncyptedBytes(): ByteString {
      var data: ByteString
      runBlocking {
        data = blob.read(this@AeadStore.storageClient.defaultBufferSizeBytes).flatten()
      }
      return data
    }
  }
}

data class AeadBlobContext(val externalAeadId: String)

private fun generateBlobKey(context: AeadBlobContext): String {
  return "/${context.externalAeadId}/${UUID.randomUUID()}"
}
