package org.wfanet.consentsignaling.common

import java.security.MessageDigest

/**
 * Generates a SHA-256 DataProviderList Hash from the dataProviderList and salt
 */
fun generateDataProviderListHash(
  dataProviderList: ByteArray,
  dataProviderListSalt: ByteArray
): ByteArray {
  val md = MessageDigest.getInstance("SHA-256")
  md.update(dataProviderListSalt)
  return md.digest(dataProviderList)
    .map { String.format("%02X", it) }
    .joinToString(separator = "").toByteArray()
}
