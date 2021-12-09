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
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Random
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement.Result as MeasurementResult
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.api.v2alpha.copy
import org.wfanet.measurement.api.v2alpha.measurementSpec
import org.wfanet.measurement.api.v2alpha.requisitionSpec
import org.wfanet.measurement.common.HexString
import org.wfanet.measurement.common.crypto.hashSha256
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.consent.crypto.hybridencryption.HybridCryptor
import org.wfanet.measurement.consent.crypto.hybridencryption.testing.ReversingHybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.testing.fakeGetHybridCryptorForCipherSuite
import org.wfanet.measurement.consent.testing.DUCHY_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_KEY_FILE

private const val NONCE = -7452112597811743614L // Hex: 9894C7134537B482
private val NONCE_HASH =
  HexString("A4EA9C2984AE1D0F7D0B026B0BB41C136FC0767E29DF40951CFE019B7D9F1CE1")
private const val NONCE_2 = -3060866405677570814L // Hex: D5859E38A0A96502
private val NONCE_2_HASH =
  HexString("45FEAA185D434E0EB4747F547F0918AA5B8403DBBD7F90D6F0D8C536E2D620D7")

// TODO Switch this to real cryptography
private val DATA_PROVIDER_PUBLIC_KEY =
  EncryptionPublicKey.newBuilder()
    .apply { data = ByteString.copyFromUtf8("some-public-key") }
    .build()
private val REQUISITION_SPEC = requisitionSpec { nonce = NONCE }
private val MEASUREMENT_SPEC = measurementSpec { nonceHashes += NONCE_HASH.bytes }

@RunWith(JUnit4::class)
class DuchyClientTest {
  @Test
  fun `verifyRequisitionFulfillment returns true when verified`() = runBlocking {
    // Compute what Duchy would store from Kingdom data.
    val hybridCryptor: HybridCryptor = ReversingHybridCryptor()
    val encryptedRequisitionSpec =
      hybridCryptor.encrypt(DATA_PROVIDER_PUBLIC_KEY, REQUISITION_SPEC.toByteString())
    val requisitionSpecHash = hashSha256(encryptedRequisitionSpec)
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
  fun `verifyRequisitionFulfillment returns false when nonce doesn't match`() = runBlocking {
    // Compute what Duchy would store from Kingdom data.
    val hybridCryptor: HybridCryptor = ReversingHybridCryptor()
    val encryptedRequisitionSpec =
      hybridCryptor.encrypt(DATA_PROVIDER_PUBLIC_KEY, REQUISITION_SPEC.toByteString())
    val requisitionSpecHash = hashSha256(encryptedRequisitionSpec)
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
  fun `verifyDataProviderParticipation returns true when verified`() = runBlocking {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE, NONCE_2)
        )
      )
      .isTrue()
  }

  @Test
  fun `verifyDataProviderParticipation returns false when missing a nonce`() = runBlocking {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE)
        )
      )
      .isFalse()
  }

  @Test
  fun `verifyDataProviderParticipation returns false when nonce mismatches hash`() = runBlocking {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE, 404L)
        )
      )
      .isFalse()
  }

  @Test
  fun `duchy sign result`() = runBlocking {
    val keyStore = InMemoryKeyStore()
    val aggregatorX509: X509Certificate = readCertificate(DUCHY_AGG_CERT_PEM_FILE)
    val someMeasurementResult =
      MeasurementResult.newBuilder()
        .apply {
          reach = MeasurementResult.Reach.newBuilder().apply { value = Random().nextLong() }.build()
          frequency = MeasurementResult.Frequency.getDefaultInstance()
        }
        .build()
    val aggregatorPrivateKeyHandleKey = "some arbitrary key"
    val aggregatorPrivateKey: PrivateKey =
      readPrivateKey(DUCHY_AGG_KEY_FILE, aggregatorX509.publicKey.algorithm)
    val aggregatorPrivateKeyHandle =
      keyStore.storePrivateKeyDer(
        aggregatorPrivateKeyHandleKey,
        ByteString.copyFrom(aggregatorPrivateKey.encoded)
      )
    val signedResult =
      signResult(
        measurementResult = someMeasurementResult,
        aggregatorKeyHandle = aggregatorPrivateKeyHandle,
        aggregatorCertificate = aggregatorX509,
      )
    assertThat(aggregatorX509.verifySignature(signedResult.data, signedResult.signature)).isTrue()
  }

  @Test
  fun `duchy encrypt result`() = runBlocking {
    val reversingHybridCryptor = ReversingHybridCryptor()
    val keyStore = InMemoryKeyStore()
    val measurementPublicKey = EncryptionPublicKey.getDefaultInstance()
    val someSignedMeasurementResult =
      SignedData.newBuilder()
        .apply {
          data = ByteString.copyFromUtf8("some measurement result")
          signature = ByteString.copyFromUtf8("some measurement result signature")
        }
        .build()
    val aggregatorPrivateKeyHandleKey = "some arbitrary key"
    val aggregatorX509: X509Certificate = readCertificate(DUCHY_AGG_CERT_PEM_FILE)
    val aggregatorPrivateKey: PrivateKey =
      readPrivateKey(DUCHY_AGG_KEY_FILE, aggregatorX509.publicKey.algorithm)
    val aggregatorPrivateKeyHandle =
      keyStore.storePrivateKeyDer(
        aggregatorPrivateKeyHandleKey,
        ByteString.copyFrom(aggregatorPrivateKey.encoded)
      )
    val encryptedSignedResult =
      encryptResult(
        signedResult = someSignedMeasurementResult,
        measurementPublicKey = measurementPublicKey,
        hybridEncryptionMapper = ::fakeGetHybridCryptorForCipherSuite
      )
    val decryptedSignedResult =
      SignedData.parseFrom(
        reversingHybridCryptor.decrypt(aggregatorPrivateKeyHandle, encryptedSignedResult)
      )
    assertThat(decryptedSignedResult).isEqualTo(someSignedMeasurementResult)
  }
}
