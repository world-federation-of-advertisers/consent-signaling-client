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

package org.wfanet.measurement.consent.client.duchy

import kotlin.test.assertTrue
import com.google.protobuf.ByteString
import org.junit.Test
import org.wfanet.measurement.consent.crypto.hybridencryption.FakeHybridCryptor
import org.wfanet.measurement.consent.crypto.keys.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.hash
import org.wfanet.measurement.consent.crypto.sign
import org.wfanet.measurement.consent.crypto.verifySignature
import org.wfanet.measurement.api.v2alpha.Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.Requisition
//import org.wfanet.measurement.api.v2alpha.Computation
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.system.v1alpha.Computation as v1Computation
import org.wfanet.measurement.system.v1alpha.Requisition as v1Requisition
import org.wfanet.measurement.consent.testing.SERVER_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.SERVER_KEY_FILE
import org.wfanet.measurement.consent.testing.KEY_ALGORITHM
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey

class DuchyClientTest {
  val dataProviderCert =
    Certificate.newBuilder()
      .also {
        it.x509Der = ByteString.copyFromUtf8(readCertificate(SERVER_CERT_PEM_FILE).toString())
      }
      .build()
  val dataProviderPrivateKey = SERVER_KEY_FILE
  val dataProviderSalt = "some-salt-0"
  val serialData = "some serial data-0"
  val hashedEncryptedRequisitionSpec = ByteString.copyFromUtf8("some-hashed-requisition-spec-0")
  val serializedDataParticipantList = ByteString.copyFromUtf8("some-serialized-participant-list-0")
  val participantListHash = ByteString.copyFromUtf8("some-hashed-participant-list-0")
  val serializedMeasurementSpec = ByteString.copyFromUtf8("some-serialized-measurement-spec")

  @Test
  fun `duchy verify edp participation signature`() {

    /** Items already known to the duchy */
    /*val computation =
      Computation.newBuilder()
        .also {
          it.serializedDataProviderList = serialData
          it.dataProviderListSalt = edpSalt
          it.measurementSpec = MeasurementSpec.newBuilder().build().toByteString()
        }
        .build()*/
    val dataProviderListHash: ByteString = hash(serializedDataParticipantList, dataProviderSalt)
    val duchyCalculatedRequisitionFingerprint =
      ByteString.copyFrom(
        requisition
          .requisitionSpecHash
          .toByteArray()
          .plus(dataProviderListHash.toByteArray())
          .plus(computation.measurementSpec.toByteArray())
      )
    /*val edpCalculatedRequisitionFingerprint =
      ByteString.copyFrom(
        requisition
          .requisitionSpecHash
          .toByteArray()
          .plus(dataProviderListHash.toByteArray())
          .plus(computation.measurementSpec.toByteArray())
      )*/
    val edpCalculatedRequisitionFingerprint = hashedEncryptedRequisitionSpec.concat(participantListHash).concat(serializedMeasurementSpec)
    val dataProviderSignedRequisitionFingerprint = readPrivateKey(SERVER_KEY_FILE, KEY_ALGORITHM).sign(readCertificate(SERVER_CERT_PEM_FILE), edpCalculatedRequisitionFingerprint)
    val requisition =
      Requisition.newBuilder()
        .also {
          it.dataProviderCertificate = ByteString.copyFromUtf8(readCertificate(SERVER_CERT_PEM_FILE).toString())
          it.dataProviderParticipationSignature = dataProviderSignature
        }
        .build()

    assertTrue(verifyEdpParticipationSignature(
      computation = computation,
      requisition = requisition,
      dataProviderCertificate = dataProviderCertificate
     ))
  }

/*  @Test
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
          hybridCryptor = FakeHybridCryptor(),
          measurementResult = result,
          duchyPrivateKeyHandle = duchyPrivateKeyHandle,
          aggregatorCertificate = aggregatorCertificate,
          measurementPublicKey = measurementConsumerPublicKey
        )
    }
  }*/
}
