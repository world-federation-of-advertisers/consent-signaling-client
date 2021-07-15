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

package org.wfanet.consentsignaling.client.duchy

import com.google.protobuf.ByteString
import org.junit.Test
import org.wfanet.consentsignaling.crypto.hybridencryption.FakeHybridCryptor
import org.wfanet.consentsignaling.crypto.keys.InMemoryKeyStore
import org.wfanet.consentsignaling.crypto.signage.FakeSigner
import org.wfanet.measurement.api.v2alpha.Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.system.v1alpha.Computation
import org.wfanet.measurement.system.v1alpha.Requisition

/**
 * These are very crappy tests however their intention is to show a "use-case" of the duchy clients
 * functions.
 *
 * These are intended for review of usage
 */
class DuchyClientTest {
  @Test
  fun `duchy verify edp participation signature`() {

    /** Items already known to the duchy */
    val computation =
      Computation.newBuilder()
        .also {
          it.dataProviderList // TODO
          it.dataProviderListSalt // TODO
          it.measurementSpec = MeasurementSpec.newBuilder().build().toByteString()
        }
        .build()

    val requisition =
      Requisition.newBuilder()
        .also {
          it.dataProviderCertificate // TODO
          it.dataProviderParticipationSignature // TODO
        }
        .build()

    val dataProviderCertificate =
      Certificate.newBuilder()
        .also {
          it.x509Der // TODO
        }
        .build()

    /**
     * TODO Verify EDP Signature after we get a working Java Security Signer
     * assertTrue(verifyEdpParticipationSignature( hybridCryptor = FakeHybridCryptor(), computation
     * = computation, requisition = requisition, dataProviderCertificate = dataProviderCertificate
     * ))
     */
  }

  @Test
  fun `duchy sign and encrypt result`() {

    /** Items already setup in the aggregator duchy */
    // Duchy Private Key Storage
    val duchyPrivateKeyId = "duchyPrivateKeyID"
    val privateKeyBytes = ByteString.copyFrom("TODO".toByteArray())
    val keystore = InMemoryKeyStore()
    keystore.storePrivateKeyDer(duchyPrivateKeyId, privateKeyBytes)
    // Duchy/Aggregator Certificate
    val aggregatorCertificate =
      Certificate.newBuilder()
        .also {
          it.x509Der // TODO
        }
        .build()
    val measurementConsumerPublicKey =
      EncryptionPublicKey.newBuilder()
        .also {
          it.type // TODO
          it.publicKeyInfo // TODO
        }
        .build()

    /** Items already known to the duchy/aggregator */
    val result =
      Measurement.Result.newBuilder()
        .also {
          // TODO
        }
        .build()

    /** Sign and Encrypt */
    val duchyPrivateKeyHandle = requireNotNull(keystore.getPrivateKeyHandle(duchyPrivateKeyId))
    Measurement.newBuilder().also {
      it.encryptedResult =
        signAndEncryptResult(
          signer = FakeSigner(),
          hybridCryptor = FakeHybridCryptor(),
          measurementResult = result,
          duchyPrivateKeyHandle = duchyPrivateKeyHandle,
          aggregatorCertificate = aggregatorCertificate,
          measurementPublicKey = measurementConsumerPublicKey
        )
    }
  }
}
