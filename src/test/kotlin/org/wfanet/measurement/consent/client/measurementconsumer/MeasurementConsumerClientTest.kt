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
import kotlinx.coroutines.runBlocking
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.hashSha256
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.consent.client.common.signMessage
import org.wfanet.measurement.consent.client.duchy.encryptResult
import org.wfanet.measurement.consent.client.duchy.signResult
import org.wfanet.measurement.consent.crypto.hybridencryption.testing.ReversingHybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.testing.fakeGetHybridCryptorForCipherSuite
import org.wfanet.measurement.consent.testing.DUCHY_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_KEY_FILE
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE
import org.wfanet.measurement.consent.testing.readSigningKeyHandle

private val keyStore = InMemoryKeyStore()
private val hybridCryptor = ReversingHybridCryptor()

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

private const val MC_PRIVATE_KEY_HANDLE_KEY = "mc1"
private val MC_PUBLIC_KEY = EncryptionPublicKey.getDefaultInstance()

private const val EDP_PRIVATE_KEY_HANDLE_KEY = "edp1"

private const val AGG_PRIVATE_KEY_HANDLE_KEY = "agg1"

private const val NONCE = -7452112597811743614 // Hex: 9894C7134537B482

@RunWith(JUnit4::class)
class MeasurementConsumerClientTest {
  @Test
  fun `createDataProviderListHash returns expect hash`() {
    val dataProviderList = ByteString.copyFromUtf8("data provider list")
    val dataProviderListSalt = ByteString.copyFromUtf8("salt")
    val concatenation = dataProviderList.concat(dataProviderListSalt)
    assertThat(createDataProviderListHash(dataProviderList, dataProviderListSalt))
      .isEqualTo(hashSha256(concatenation))
  }

  @Test
  fun `signRequisitionSpec returns valid signature`() = runBlocking {
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
  fun `encryptRequisitionSpec returns encrypted RequisitionSpec`() = runBlocking {
    val measurementPublicKey = EncryptionPublicKey.getDefaultInstance()
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
        measurementPublicKey = measurementPublicKey,
        hybridEncryptionMapper = ::fakeGetHybridCryptorForCipherSuite
      )

    val privateKeyHandle = keyStore.getPrivateKeyHandle(EDP_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(privateKeyHandle)
    val decryptedSignedRequisitionSpec =
      SignedData.parseFrom(hybridCryptor.decrypt(privateKeyHandle, encryptedSignedRequisitionSpec))
    assertThat(decryptedSignedRequisitionSpec).isEqualTo(signedRequisitionSpec)
  }

  @Test
  fun `signMeasurementSpec returns valid signature`() = runBlocking {
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
  fun `signEncryptionPublicKey returns valid signature`() = runBlocking {
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
  fun `decryptResult returns decrypted MeasurementResult`() = runBlocking {
    // Encrypt a Result (as SignedData) using the Duchy Aggregator Functions
    val signedResult = signResult(FAKE_MEASUREMENT_RESULT, AGGREGATOR_SIGNING_KEY)
    val encryptedSignedResult =
      encryptResult(
        signedResult = signedResult,
        measurementPublicKey = MC_PUBLIC_KEY,
        hybridEncryptionMapper = ::fakeGetHybridCryptorForCipherSuite
      )

    // Decrypt the SignedData Result
    val privateKeyHandle = keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(privateKeyHandle)
    val decryptedSignedDataResult =
      decryptResult(encryptedSignedResult, privateKeyHandle, ::fakeGetHybridCryptorForCipherSuite)
    val decryptedResult = Measurement.Result.parseFrom(decryptedSignedDataResult.data)

    assertThat(signedResult).isEqualTo(decryptedSignedDataResult)
    assertThat(
        verifyResult(
          resultSignature = decryptedSignedDataResult.signature,
          measurementResult = decryptedResult,
          aggregatorCertificate = AGGREGATOR_SIGNING_KEY.certificate,
        )
      )
      .isTrue()
    assertThat(FAKE_MEASUREMENT_RESULT.reach.value).isEqualTo(decryptedResult.reach.value)
  }

  @Test
  fun `verifyResult verifies valid MeasurementResult signature`() = runBlocking {
    val signingKeyHandle = AGGREGATOR_SIGNING_KEY
    val signedResult: SignedData = signMessage(FAKE_MEASUREMENT_RESULT, signingKeyHandle)

    assertThat(
        verifyResult(
          resultSignature = signedResult.signature,
          measurementResult = FAKE_MEASUREMENT_RESULT,
          aggregatorCertificate = signingKeyHandle.certificate,
        )
      )
      .isTrue()
  }

  @Test
  fun `verifiesEncryptionPublicKey verifies valid EncryptionPublicKey signature`() = runBlocking {
    val signingKeyHandle = EDP_SIGNING_KEY
    val signedEncryptionPublicKey: SignedData =
      signMessage(FAKE_ENCRYPTION_PUBLIC_KEY, signingKeyHandle)

    assertThat(
        verifyEncryptionPublicKey(
          encryptionPublicKeySignature = signedEncryptionPublicKey.signature,
          encryptionPublicKey = FAKE_ENCRYPTION_PUBLIC_KEY,
          edpCertificate = signingKeyHandle.certificate,
        )
      )
      .isTrue()
  }

  companion object {
    private val MC_SIGNING_KEY = readSigningKeyHandle(MC_1_CERT_PEM_FILE, MC_1_KEY_FILE)
    private val EDP_SIGNING_KEY = readSigningKeyHandle(EDP_1_CERT_PEM_FILE, EDP_1_KEY_FILE)
    private val AGGREGATOR_SIGNING_KEY =
      readSigningKeyHandle(DUCHY_AGG_CERT_PEM_FILE, DUCHY_AGG_KEY_FILE)

    @BeforeClass
    @JvmStatic
    fun initializePrivateKeyKeystore() {
      runBlocking {
        keyStore.storePrivateKeyDer(
          MC_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(MC_1_KEY_FILE, MC_SIGNING_KEY.certificate.publicKey.algorithm).encoded
          )
        )
        keyStore.storePrivateKeyDer(
          EDP_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(EDP_1_KEY_FILE, EDP_SIGNING_KEY.certificate.publicKey.algorithm).encoded
          )
        )
        keyStore.storePrivateKeyDer(
          AGG_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(
                DUCHY_AGG_KEY_FILE,
                AGGREGATOR_SIGNING_KEY.certificate.publicKey.algorithm
              )
              .encoded
          )
        )
      }
    }
  }
}
