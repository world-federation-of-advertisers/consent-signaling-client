// Copyright 2021 The Cross-Media Measurement Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
