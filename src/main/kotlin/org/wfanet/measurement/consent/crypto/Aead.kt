package org.wfanet.measurement.consent.crypto

import com.google.protobuf.ByteString

/** TODO: This should be moved to common-jvm crytpo */
interface Aead {
  fun encrypt(data: ByteString): ByteString

  fun decrypt(encryptedData: ByteString): ByteString
}
