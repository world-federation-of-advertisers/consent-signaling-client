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

package org.wfanet.measurement.consent.client.measurementconsumer

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import com.google.protobuf.kotlin.toByteStringUtf8
import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXReason
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.EventGroupKt
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.api.v2alpha.copy
import org.wfanet.measurement.common.crypto.Hashing
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.tink.TinkPrivateKeyHandle
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toEncryptionPublicKey
import org.wfanet.measurement.consent.client.dataprovider.encryptMetadata
import org.wfanet.measurement.consent.client.duchy.encryptResult
import org.wfanet.measurement.consent.client.duchy.signResult
import org.wfanet.measurement.consent.testing.DUCHY_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_KEY_FILE
import org.wfanet.measurement.consent.testing.EDP_1_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE
import org.wfanet.measurement.consent.testing.readSigningKeyHandle

private val FAKE_MEASUREMENT_SPEC = MeasurementSpec.newBuilder().build()

private val FAKE_ENCRYPTION_PUBLIC_KEY =
  EncryptionPublicKey.newBuilder().apply { data = ByteString.copyFromUtf8("testPublicKey") }.build()

private val FAKE_MEASUREMENT_RESULT =
  Measurement.Result.newBuilder()
    .apply {
      reach = Measurement.Result.Reach.newBuilder().apply { value = 10 }.build()
      frequency =
        Measurement.Result.Frequency.newBuilder()
          .apply { putAllRelativeFrequencyDistribution(mapOf(1L to 1.0, 2L to 2.0, 3L to 3.0)) }
          .build()
    }
    .build()

private val FAKE_EVENT_GROUP_METADATA =
  EventGroupKt.metadata { eventGroupMetadataDescriptor = "fake descriptor" }

private const val NONCE = -7452112597811743614 // Hex: 9894C7134537B482

@RunWith(JUnit4::class)
class MeasurementConsumerClientTest {
  @Test
  fun `createDataProviderListHash returns expect hash`() {
    val dataProviderList = ByteString.copyFromUtf8("data provider list")
    val dataProviderListSalt = ByteString.copyFromUtf8("salt")
    val concatenation = dataProviderList.concat(dataProviderListSalt)
    assertThat(createDataProviderListHash(dataProviderList, dataProviderListSalt))
      .isEqualTo(Hashing.hashSha256(concatenation))
  }

  @Test
  fun `signRequisitionSpec returns valid signature`() {
    val requisitionSpec =
      RequisitionSpec.newBuilder()
        .apply {
          measurementPublicKey = FAKE_ENCRYPTION_PUBLIC_KEY.toByteString()
          nonce = NONCE
        }
        .build()

    val signedResult =
      signRequisitionSpec(
        requisitionSpec = requisitionSpec,
        measurementConsumerSigningKey = MC_SIGNING_KEY,
      )

    assertThat(
        MC_SIGNING_KEY.certificate.verifySignature(signedResult.data, signedResult.signature)
      )
      .isTrue()
  }

  @Test
  fun `encryptRequisitionSpec returns encrypted RequisitionSpec`() {
    val signedRequisitionSpec =
      SignedData.newBuilder()
        .apply {
          data = ByteString.copyFromUtf8("testRequisitionSpec")
          signature = ByteString.copyFromUtf8("testRequisitionSpecSignature")
        }
        .build()

    val encryptedSignedRequisitionSpec =
      encryptRequisitionSpec(
        signedRequisitionSpec = signedRequisitionSpec,
        measurementPublicKey = MEASUREMENT_PUBLIC_KEY
      )

    val decryptedSignedRequisitionSpec =
      SignedData.parseFrom(MEASUREMENT_PRIVATE_KEY.hybridDecrypt(encryptedSignedRequisitionSpec))
    assertThat(decryptedSignedRequisitionSpec).isEqualTo(signedRequisitionSpec)
  }

  @Test
  fun `signMeasurementSpec returns valid signature`() {
    val signedMeasurementSpec =
      signMeasurementSpec(
        measurementSpec = FAKE_MEASUREMENT_SPEC,
        measurementConsumerSigningKey = MC_SIGNING_KEY,
      )

    assertThat(
        MC_SIGNING_KEY.certificate.verifySignature(
          signedMeasurementSpec.data,
          signedMeasurementSpec.signature
        )
      )
      .isTrue()
  }

  @Test
  fun `signEncryptionPublicKey returns valid signature`() {
    val mcEncryptionPublicKey =
      EncryptionPublicKey.newBuilder()
        .apply { data = ByteString.copyFromUtf8("testMCPublicKey") }
        .build()

    val signedEncryptionPublicKey =
      signEncryptionPublicKey(
        encryptionPublicKey = mcEncryptionPublicKey,
        signingKey = MC_SIGNING_KEY,
      )

    assertThat(
        MC_SIGNING_KEY.certificate.verifySignature(
          signedEncryptionPublicKey.data,
          signedEncryptionPublicKey.signature
        )
      )
      .isTrue()
  }

  @Test
  fun `decryptResult returns decrypted MeasurementResult`() {
    // Encrypt a Result (as SignedData) using the Duchy Aggregator Functions
    val signedResult = signResult(FAKE_MEASUREMENT_RESULT, AGGREGATOR_SIGNING_KEY)
    val encryptedSignedResult =
      encryptResult(signedResult = signedResult, measurementPublicKey = MEASUREMENT_PUBLIC_KEY)

    // Decrypt the SignedData Result
    val decryptedSignedDataResult = decryptResult(encryptedSignedResult, MEASUREMENT_PRIVATE_KEY)
    val decryptedResult = Measurement.Result.parseFrom(decryptedSignedDataResult.data)

    assertThat(signedResult).isEqualTo(decryptedSignedDataResult)
    assertThat(FAKE_MEASUREMENT_RESULT.reach.value).isEqualTo(decryptedResult.reach.value)
  }

  @Test
  fun `verifyResult does not throw when signed Result is valid`() {
    val signingKeyHandle = AGGREGATOR_SIGNING_KEY
    val signedResult: SignedData = FAKE_MEASUREMENT_RESULT.serializeAndSign(signingKeyHandle)

    verifyResult(signedResult, AGGREGATOR_SIGNING_KEY.certificate, AGGREGATOR_ROOT_CERT)
  }

  @Test
  fun `verifyResult throws when signature is invalid`() {
    val signingKeyHandle = AGGREGATOR_SIGNING_KEY
    val signedResult: SignedData =
      FAKE_MEASUREMENT_RESULT.serializeAndSign(signingKeyHandle).copy {
        signature = "garbage".toByteStringUtf8()
      }

    assertFailsWith<SignatureException> {
      verifyResult(signedResult, AGGREGATOR_SIGNING_KEY.certificate, AGGREGATOR_ROOT_CERT)
    }
  }

  @Test
  fun `verifyResult throws when certificate path is invalid`() {
    val signingKeyHandle = AGGREGATOR_SIGNING_KEY
    val signedResult: SignedData = FAKE_MEASUREMENT_RESULT.serializeAndSign(signingKeyHandle)
    val incorrectIssuer = EDP_TRUSTED_ISSUER

    val exception =
      assertFailsWith<CertPathValidatorException> {
        verifyResult(signedResult, AGGREGATOR_SIGNING_KEY.certificate, incorrectIssuer)
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun `verifiesEncryptionPublicKey does not throw when signed EncryptionPublicKey is valid`() {
    val signingKeyHandle = EDP_SIGNING_KEY
    val signedEncryptionPublicKey: SignedData =
      FAKE_ENCRYPTION_PUBLIC_KEY.serializeAndSign(signingKeyHandle)

    verifyEncryptionPublicKey(
      signedEncryptionPublicKey,
      signingKeyHandle.certificate,
      EDP_TRUSTED_ISSUER
    )
  }

  @Test
  fun `decryptMetadata returns decrypted Metadata`() {
    val encryptedMetadata = encryptMetadata(FAKE_EVENT_GROUP_METADATA, MC_PUBLIC_KEY)

    val metadata =
      decryptMetadata(
        encryptedMetadata = encryptedMetadata,
        measurementConsumerPrivateKey = MC_PRIVATE_KEY
      )

    assertThat(metadata).isEqualTo(FAKE_EVENT_GROUP_METADATA)
  }

  companion object {
    private val MC_SIGNING_KEY = readSigningKeyHandle(MC_1_CERT_PEM_FILE, MC_1_KEY_FILE)
    private val MC_PRIVATE_KEY = TinkPrivateKeyHandle.generateEcies()
    private val MC_PUBLIC_KEY = MC_PRIVATE_KEY.publicKey.toEncryptionPublicKey()

    private val EDP_SIGNING_KEY = readSigningKeyHandle(EDP_1_CERT_PEM_FILE, EDP_1_KEY_FILE)
    private val EDP_TRUSTED_ISSUER = readCertificate(EDP_1_ROOT_CERT_PEM_FILE)

    private val AGGREGATOR_SIGNING_KEY =
      readSigningKeyHandle(DUCHY_AGG_CERT_PEM_FILE, DUCHY_AGG_KEY_FILE)
    private val AGGREGATOR_ROOT_CERT = readCertificate(DUCHY_AGG_ROOT_CERT_PEM_FILE)

    private val MEASUREMENT_PRIVATE_KEY = TinkPrivateKeyHandle.generateEcies()
    private val MEASUREMENT_PUBLIC_KEY = MEASUREMENT_PRIVATE_KEY.publicKey.toEncryptionPublicKey()
  }
}
