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

package org.wfanet.measurement.consent.crypto.testing

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.HybridCipherSuite
import org.wfanet.measurement.consent.crypto.hybridencryption.testing.ReversingHybridCryptor

@RunWith(JUnit4::class)
class FakeUtilsTest {

  @Test
  fun `supported cipher suite maps to to ReversingHybridCryptor`() {
    val cipherSuite =
      HybridCipherSuite.newBuilder()
        .apply {
          kem = HybridCipherSuite.KeyEncapsulationMechanism.ECDH_P256_HKDF_HMAC_SHA256
          dem = HybridCipherSuite.DataEncapsulationMechanism.AES_128_GCM
        }
        .build()
    val hybridCryptor = fakeGetHybridCryptorForCipherSuite(cipherSuite)
    assertThat(hybridCryptor).isInstanceOf(ReversingHybridCryptor::class.java)
  }

  @Test
  fun `unsupported cipher suite maps to to ReversingHybridCryptor`() {
    val cipherSuite =
      HybridCipherSuite.newBuilder()
        .apply {
          kem = HybridCipherSuite.KeyEncapsulationMechanism.KEY_ENCAPSULATION_MECHANISM_UNSPECIFIED
          dem =
            HybridCipherSuite.DataEncapsulationMechanism.DATA_ENCAPSULATION_MECHANISM_UNSPECIFIED
        }
        .build()
    val hybridCryptor = fakeGetHybridCryptorForCipherSuite(cipherSuite)
    assertThat(hybridCryptor).isInstanceOf(ReversingHybridCryptor::class.java)
  }
}
