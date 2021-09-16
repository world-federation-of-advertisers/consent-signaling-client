package org.wfanet.measurement.consent.crypto

import com.google.crypto.tink.Aead as TinkAead
import com.google.protobuf.ByteString

/** TODO: This should be moved to common-jvm crytpo */
class TinkAead(val aead: TinkAead) : Aead {

  override fun encrypt(data: ByteString): ByteString {
    return ByteString.copyFrom(aead.encrypt(data.toByteArray(), byteArrayOf()))
  }

  override fun decrypt(encryptedData: ByteString): ByteString {
    return ByteString.copyFrom(aead.decrypt(encryptedData.toByteArray(), byteArrayOf()))
  }
}
