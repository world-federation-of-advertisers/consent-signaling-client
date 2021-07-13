package org.wfanet.consentsignaling.crypto.hash

import com.google.protobuf.ByteString
import java.security.MessageDigest

object CommonConstants {
  const val HASH_ALGORITHM = "SHA-256"
}
/** Generates a SHA-256 DataProviderList Hash from the dataProviderList and salt */
fun generateDataProviderListHash(
  dataProviderList: ByteString,
  dataProviderListSalt: ByteString
): ByteString {
  val sha256MessageDigest = MessageDigest.getInstance(CommonConstants.HASH_ALGORITHM)
  sha256MessageDigest.update(dataProviderListSalt.toByteArray())
  return ByteString.copyFrom(sha256MessageDigest.digest(dataProviderList.toByteArray()))
}
