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

package org.wfanet.measurement.consent.crypto

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

private val DATA = ByteString.copyFromUtf8("some-data-to-hash")
private val ALT_DATA = ByteString.copyFromUtf8("some-alternative-data")

private val SALT = ByteString.copyFromUtf8("some-salt")
private val ALT_SALT = ByteString.copyFromUtf8("some-alternative-salt")

@RunWith(JUnit4::class)
class HashingTest {
  @Test
  fun `hash same data with same salt yields same value`() {
    val hashedData1 = hashSha256(DATA, SALT)
    val hashedData2 = hashSha256(DATA, SALT)
    assertThat(hashedData1).isEqualTo(hashedData2)
  }

  fun `hash same data without salt yields same value`() {
    val hashedData1 = hashSha256(DATA)
    val hashedData2 = hashSha256(DATA)
    assertThat(hashedData1).isEqualTo(hashedData2)
  }

  fun `hash same data with different salt yields different values`() {
    val hashedData1 = hashSha256(DATA, SALT)
    val hashedData2 = hashSha256(DATA, ALT_SALT)
    assertThat(hashedData1).isNotEqualTo(hashedData2)
  }

  @Test
  fun `hash different data with same salt yields different values`() {
    val hashedData1 = hashSha256(DATA)
    val hashedData2 = hashSha256(ALT_DATA)
    assertThat(hashedData1).isNotEqualTo(hashedData2)
  }

  @Test
  fun `hash different data without salt yields different values`() {
    val hashedData1 = hashSha256(DATA, SALT)
    val hashedData2 = hashSha256(ALT_DATA, SALT)
    assertThat(hashedData1).isNotEqualTo(hashedData2)
  }
}
