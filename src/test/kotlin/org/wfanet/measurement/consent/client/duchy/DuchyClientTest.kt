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

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import com.google.protobuf.kotlin.toByteStringUtf8
import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXReason
import java.util.Random
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement.Result as MeasurementResult
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.api.v2alpha.copy
import org.wfanet.measurement.api.v2alpha.measurementSpec
import org.wfanet.measurement.api.v2alpha.requisition
import org.wfanet.measurement.api.v2alpha.signedData
import org.wfanet.measurement.common.HexString
import org.wfanet.measurement.common.crypto.Hashing
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.tink.TinkPrivateKeyHandle
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toEncryptionPublicKey
import org.wfanet.measurement.consent.client.dataprovider.computeRequisitionFingerprint
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.readSigningKeyHandle

private const val NONCE = -7452112597811743614L // Hex: 9894C7134537B482
private val NONCE_HASH =
  HexString("A4EA9C2984AE1D0F7D0B026B0BB41C136FC0767E29DF40951CFE019B7D9F1CE1")
private const val NONCE_2 = -3060866405677570814L // Hex: D5859E38A0A96502
private val NONCE_2_HASH =
  HexString("45FEAA185D434E0EB4747F547F0918AA5B8403DBBD7F90D6F0D8C536E2D620D7")

private val MEASUREMENT_SPEC = measurementSpec { nonceHashes += NONCE_HASH.bytes }

private val FAKE_EL_GAMAL_PUBLIC_KEY = ElGamalPublicKey.getDefaultInstance()

@RunWith(JUnit4::class)
class DuchyClientTest {
  @Test
  fun `computeRequisitionFingerprint returns Requisition fingerprint`() {
    // Compute what Duchy would store from Kingdom data.
    val encryptedRequisitionSpec = "Encrypted RequisitionSpec".toByteStringUtf8()
    val requisitionSpecHash = Hashing.hashSha256(encryptedRequisitionSpec)
    val serializedMeasurementSpec = MEASUREMENT_SPEC.toByteString()

    val requisitionFingerprint =
      computeRequisitionFingerprint(serializedMeasurementSpec, requisitionSpecHash)

    // Verify that fingerprint matches the same one that would be computed by Data Provider.
    assertThat(requisitionFingerprint)
      .isEqualTo(
        computeRequisitionFingerprint(
          requisition {
            measurementSpec = signedData { data = serializedMeasurementSpec }
            this.encryptedRequisitionSpec = encryptedRequisitionSpec
          }
        )
      )
  }

  @Test
  fun `verifyRequisitionFulfillment returns true when verified`() {
    // Compute what Duchy would store from Kingdom data.
    val encryptedRequisitionSpec = "Encrypted RequisitionSpec".toByteStringUtf8()
    val requisitionSpecHash = Hashing.hashSha256(encryptedRequisitionSpec)
    val serializedMeasurementSpec = MEASUREMENT_SPEC.toByteString()
    val requisitionFingerprint =
      computeRequisitionFingerprint(serializedMeasurementSpec, requisitionSpecHash)
    val requisition = Requisition(requisitionFingerprint, NONCE_HASH.bytes)

    assertThat(
        verifyRequisitionFulfillment(
          measurementSpec = MEASUREMENT_SPEC,
          requisition = requisition,
          requisitionFingerprint = requisitionFingerprint,
          nonce = NONCE
        )
      )
      .isTrue()
  }

  @Test
  fun `verifyRequisitionFulfillment returns false when nonce doesn't match`() {
    // Compute what Duchy would store from Kingdom data.
    val encryptedRequisitionSpec = "Encrypted RequisitionSpec".toByteStringUtf8()
    val requisitionSpecHash = Hashing.hashSha256(encryptedRequisitionSpec)
    val serializedMeasurementSpec = MEASUREMENT_SPEC.toByteString()
    val requisitionFingerprint =
      computeRequisitionFingerprint(serializedMeasurementSpec, requisitionSpecHash)
    val requisition = Requisition(requisitionFingerprint, NONCE_HASH.bytes)

    assertThat(
        verifyRequisitionFulfillment(
          measurementSpec = MEASUREMENT_SPEC,
          requisition = requisition,
          requisitionFingerprint = requisitionFingerprint,
          nonce = 404L
        )
      )
      .isFalse()
  }

  @Test
  fun `verifyDataProviderParticipation returns true when verified`() {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE, NONCE_2)
        )
      )
      .isTrue()
  }

  @Test
  fun `verifyDataProviderParticipation returns false when missing a nonce`() {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE)
        )
      )
      .isFalse()
  }

  @Test
  fun `verifyDataProviderParticipation returns false when nonce mismatches hash`() {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE, 404L)
        )
      )
      .isFalse()
  }

  @Test
  fun `duchy sign result`() {
    val someMeasurementResult =
      MeasurementResult.newBuilder()
        .apply {
          reach = MeasurementResult.Reach.newBuilder().apply { value = Random().nextLong() }.build()
          frequency = MeasurementResult.Frequency.getDefaultInstance()
        }
        .build()
    val signedResult =
      signResult(
        measurementResult = someMeasurementResult,
        aggregatorSigningKey = AGGREGATOR_SIGNING_KEY,
      )
    assertThat(
        AGGREGATOR_SIGNING_KEY.certificate.verifySignature(
          signedResult.data,
          signedResult.signature
        )
      )
      .isTrue()
  }

  @Test
  fun `duchy encrypt result`() {
    val measurementEncryptionKey = TinkPrivateKeyHandle.generateEcies()
    val measurementPublicKey = measurementEncryptionKey.publicKey.toEncryptionPublicKey()
    val signedMeasurementResult =
      SignedData.newBuilder()
        .apply {
          data = ByteString.copyFromUtf8("some measurement result")
          signature = ByteString.copyFromUtf8("some measurement result signature")
        }
        .build()

    val encryptedSignedResult =
      encryptResult(
        signedResult = signedMeasurementResult,
        measurementPublicKey = measurementPublicKey
      )

    val decryptedSignedResult =
      SignedData.parseFrom(measurementEncryptionKey.hybridDecrypt(encryptedSignedResult))
    assertThat(decryptedSignedResult).isEqualTo(signedMeasurementResult)
  }

  @Test
  fun `verifyElGamalPublicKey does not throw exception when signature is valid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedData =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle)

    verifyElGamalPublicKey(
      signedElGamalPublicKey.data,
      signedElGamalPublicKey.signature,
      signingKeyHandle.certificate,
      DUCHY_TRUSTED_ISSUER
    )
  }

  @Test
  fun `verifyElGamalPublicKey throws when certificate path is invalid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedData =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle)
    val incorrectIssuer = DUCHY_SIGNING_KEY.certificate

    val exception =
      assertFailsWith<CertPathValidatorException> {
        verifyElGamalPublicKey(
          signedElGamalPublicKey.data,
          signedElGamalPublicKey.signature,
          signingKeyHandle.certificate,
          incorrectIssuer
        )
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun `verifyElGamalPublicKey throws when signature is invalid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedData =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle)
    val badSignature: ByteString =
      signedElGamalPublicKey.signature.concat("garbage".toByteStringUtf8())

    assertFailsWith<SignatureException> {
      verifyElGamalPublicKey(
        signedElGamalPublicKey.data,
        badSignature,
        signingKeyHandle.certificate,
        DUCHY_TRUSTED_ISSUER
      )
    }
  }

  companion object {
    private val AGGREGATOR_SIGNING_KEY =
      readSigningKeyHandle(DUCHY_AGG_CERT_PEM_FILE, DUCHY_AGG_KEY_FILE)

    private val DUCHY_SIGNING_KEY =
      readSigningKeyHandle(DUCHY_1_NON_AGG_CERT_PEM_FILE, DUCHY_1_NON_AGG_KEY_FILE)
    private val DUCHY_TRUSTED_ISSUER = readCertificate(DUCHY_1_NON_AGG_ROOT_CERT_PEM_FILE)
  }
}
