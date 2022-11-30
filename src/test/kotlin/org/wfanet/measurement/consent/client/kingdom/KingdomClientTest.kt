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

package org.wfanet.measurement.consent.client.kingdom

import com.google.protobuf.ByteString
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.consent.client.measurementconsumer.signMeasurementSpec
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE
import org.wfanet.measurement.consent.testing.MC_1_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.readSigningKeyHandle

private val MEASUREMENT_PUBLIC_KEY =
  EncryptionPublicKey.newBuilder()
    .apply { data = ByteString.copyFromUtf8("some-public-key") }
    .build()

private val FAKE_MEASUREMENT_SPEC =
  MeasurementSpec.newBuilder()
    .apply { measurementPublicKey = MEASUREMENT_PUBLIC_KEY.toByteString() }
    .build()

@RunWith(JUnit4::class)
class KingdomClientTest {
  @Test
  fun `verifyMeasurementSpec does not throw when signed MeasurementSpec is valid`() = runBlocking {
    val signedMeasurementSpec: SignedData =
      signMeasurementSpec(FAKE_MEASUREMENT_SPEC, MC_SIGNING_KEY)

    verifyMeasurementSpec(signedMeasurementSpec, MC_SIGNING_KEY.certificate, MC_TRUSTED_ISSUER)
  }

  companion object {
    private val MC_SIGNING_KEY = readSigningKeyHandle(MC_1_CERT_PEM_FILE, MC_1_KEY_FILE)
    private val MC_TRUSTED_ISSUER = readCertificate(MC_1_ROOT_CERT_PEM_FILE)
  }
}
