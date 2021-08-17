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

package org.wfanet.measurement.consent.client.dataprovider

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import java.security.cert.X509Certificate
import java.util.Base64
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.HybridCipherSuite
import org.wfanet.measurement.api.v2alpha.MeasurementSpec
import org.wfanet.measurement.api.v2alpha.Requisition
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey
import org.wfanet.measurement.consent.client.measurementconsumer.encryptRequisitionSpec
import org.wfanet.measurement.consent.client.measurementconsumer.signRequisitionSpec
import org.wfanet.measurement.consent.crypto.hashSha256
import org.wfanet.measurement.consent.crypto.hybridencryption.testing.ReversingHybridCryptor
import org.wfanet.measurement.consent.crypto.keystore.testing.InMemoryKeyStore
import org.wfanet.measurement.consent.crypto.signMessage
import org.wfanet.measurement.consent.crypto.testing.fakeGetHybridCryptorForCipherSuite
import org.wfanet.measurement.consent.crypto.verifySignature
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_KEY_FILE
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE

private val MEASUREMENT_PUBLIC_KEY =
  EncryptionPublicKey.newBuilder()
    .apply { publicKeyInfo = ByteString.copyFromUtf8("some-public-key") }
    .build()
private val SOME_DATA_PROVIDER_LIST_SALT = ByteString.copyFromUtf8("some-salt-0")
private val SOME_SERIALIZED_DATA_PROVIDER_LIST = ByteString.copyFromUtf8("some-data-provider-list")
private val SOME_SERIALIZED_MEASUREMENT_SPEC =
  ByteString.copyFromUtf8("some-serialized-measurement-spec")

private val keyStore = InMemoryKeyStore()
private val hybridCryptor = ReversingHybridCryptor()

private val FAKE_MEASUREMENT_SPEC =
  MeasurementSpec.newBuilder()
    .apply {
      cipherSuite = HybridCipherSuite.getDefaultInstance()
      measurementPublicKey = MEASUREMENT_PUBLIC_KEY.toByteString()
    }
    .build()

private val FAKE_REQUISITION_SPEC =
  RequisitionSpec.newBuilder()
    .apply {
      dataProviderListHash =
        hashSha256(SOME_SERIALIZED_DATA_PROVIDER_LIST, SOME_DATA_PROVIDER_LIST_SALT)
      measurementPublicKey = MEASUREMENT_PUBLIC_KEY.toByteString()
    }
    .build()

private val FAKE_EL_GAMAL_PUBLIC_KEY = ElGamalPublicKey.getDefaultInstance()

private val MC_CERTIFICATE: X509Certificate = readCertificate(MC_1_CERT_PEM_FILE)
private const val MC_PRIVATE_KEY_HANDLE_KEY = "mc1"

private val EDP_CERTIFICATE: X509Certificate = readCertificate(EDP_1_CERT_PEM_FILE)
private const val EDP_PRIVATE_KEY_HANDLE_KEY = "edp1"
private val EDP_PUBLIC_KEY = EncryptionPublicKey.getDefaultInstance()

private val DUCHY_CERTIFICATE: X509Certificate = readCertificate(DUCHY_1_NON_AGG_CERT_PEM_FILE)
private const val DUCHY_PRIVATE_KEY_HANDLE_KEY = "duchy1"

@RunWith(JUnit4::class)
class DataProviderClientTest {
  companion object {
    @BeforeClass
    @JvmStatic
    fun initializePrivateKeyKeystore() {
      runBlocking {
        keyStore.storePrivateKeyDer(
          MC_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(MC_1_KEY_FILE, MC_CERTIFICATE.publicKey.algorithm).encoded
          )
        )
        keyStore.storePrivateKeyDer(
          EDP_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(EDP_1_KEY_FILE, EDP_CERTIFICATE.publicKey.algorithm).encoded
          )
        )
        keyStore.storePrivateKeyDer(
          DUCHY_PRIVATE_KEY_HANDLE_KEY,
          ByteString.copyFrom(
            readPrivateKey(DUCHY_1_NON_AGG_KEY_FILE, DUCHY_CERTIFICATE.publicKey.algorithm).encoded
          )
        )
      }
    }
  }

  private val someEncryptedRequisitionSpec =
    hybridCryptor.encrypt(MEASUREMENT_PUBLIC_KEY, FAKE_REQUISITION_SPEC.toByteString())

  @Test
  fun `data provider calculates requisition participation signature`() = runBlocking {
    val privateKeyHandle = keyStore.getPrivateKeyHandle(EDP_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(privateKeyHandle)
    val requisition =
      Requisition.newBuilder()
        .apply {
          encryptedRequisitionSpec = someEncryptedRequisitionSpec
          measurementSpec =
            SignedData.newBuilder().apply { data = SOME_SERIALIZED_MEASUREMENT_SPEC }.build()
        }
        .build()
    val dataProviderParticipation: SignedData =
      createParticipationSignature(
        hybridCryptor = hybridCryptor,
        requisition = requisition,
        privateKeyHandle = privateKeyHandle,
        dataProviderCertificate = EDP_CERTIFICATE
      )
    assertThat(Base64.getEncoder().encodeToString(dataProviderParticipation.data.toByteArray()))
      .isEqualTo(
        "bnVXV7tDjYDhNP8KXXjP8PZ0Iu1fRT9/E5E1vjfDcr8PkHDERRYb2Dd0CVCsKEJa5IbodPlqp9Y" +
          "awikye4ihpXNvbWUtc2VyaWFsaXplZC1tZWFzdXJlbWVudC1zcGVj"
      )
    assertTrue(EDP_CERTIFICATE.verifySignature(dataProviderParticipation))
  }

  @Test
  fun `verifyMeasurementSpec verifies valid MeasurementSpec signature`() = runBlocking {
    val privateKeyHandle = keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(privateKeyHandle)
    val signedMeasurementSpec =
      signMessage<MeasurementSpec>(
        message = FAKE_MEASUREMENT_SPEC,
        privateKeyHandle = privateKeyHandle,
        certificate = MC_CERTIFICATE
      )

    assertTrue(
      verifyMeasurementSpec(
        measurementSpecSignature = signedMeasurementSpec.signature,
        measurementSpec = FAKE_MEASUREMENT_SPEC,
        measurementConsumerCertificate = MC_CERTIFICATE,
      )
    )
  }

  @Test
  fun `decryptRequistionSpec returns decrypted RequistionSpec`() = runBlocking {
    val hybridCipherSuite = HybridCipherSuite.getDefaultInstance()
    // Encrypt a RequisitionSpec (as SignedData) using the Measurement Consumer Functions
    val measurementConsumerPrivateKeyHandle =
      keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(measurementConsumerPrivateKeyHandle)
    val signedRequisitionSpec =
      signRequisitionSpec(
        FAKE_REQUISITION_SPEC,
        measurementConsumerPrivateKeyHandle,
        MC_CERTIFICATE
      )
    val encryptedRequisitionSpec =
      encryptRequisitionSpec(
        signedRequisitionSpec = signedRequisitionSpec,
        measurementPublicKey = EDP_PUBLIC_KEY,
        cipherSuite = hybridCipherSuite,
        hybridEncryptionMapper = ::fakeGetHybridCryptorForCipherSuite
      )

    // Decrypt the SignedData RequisitionSpec
    val privateKeyHandle = keyStore.getPrivateKeyHandle(EDP_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(privateKeyHandle)
    val decryptedSignedDataRequisitionSpec =
      decryptRequisitionSpec(
        encryptedRequisitionSpec,
        privateKeyHandle,
        hybridCipherSuite,
        ::fakeGetHybridCryptorForCipherSuite
      )
    val decryptedRequisitionSpec =
      RequisitionSpec.parseFrom(decryptedSignedDataRequisitionSpec.data)

    assertThat(signedRequisitionSpec).isEqualTo(decryptedSignedDataRequisitionSpec)
    assertTrue(
      verifyRequisitionSpec(
        requisitionSpecSignature = decryptedSignedDataRequisitionSpec.signature,
        requisitionSpec = decryptedRequisitionSpec,
        measurementConsumerCertificate = MC_CERTIFICATE,
        measurementSpec = FAKE_MEASUREMENT_SPEC,
      )
    )
  }

  @Test
  fun `verifyRequistionSpec verifies valid RequistionSpec signature`() = runBlocking {
    val measurementConsumerPrivateKeyHandle =
      keyStore.getPrivateKeyHandle(MC_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(measurementConsumerPrivateKeyHandle)
    val signedRequisitionSpec =
      signRequisitionSpec(
        FAKE_REQUISITION_SPEC,
        measurementConsumerPrivateKeyHandle,
        MC_CERTIFICATE
      )

    assertTrue(
      verifyRequisitionSpec(
        requisitionSpecSignature = signedRequisitionSpec.signature,
        requisitionSpec = FAKE_REQUISITION_SPEC,
        measurementConsumerCertificate = MC_CERTIFICATE,
        measurementSpec = FAKE_MEASUREMENT_SPEC,
      )
    )
  }

  @Test
  fun `verifiesElgamalPublicKey verifies valid EncryptionPublicKey signature`() = runBlocking {
    val privateKeyHandle = keyStore.getPrivateKeyHandle(DUCHY_PRIVATE_KEY_HANDLE_KEY)
    checkNotNull(privateKeyHandle)
    val signedElGamalPublicKey =
      signMessage<ElGamalPublicKey>(
        message = FAKE_EL_GAMAL_PUBLIC_KEY,
        privateKeyHandle = privateKeyHandle,
        certificate = DUCHY_CERTIFICATE
      )

    assertTrue(
      verifyElGamalPublicKey(
        elGamalPublicKeySignature = signedElGamalPublicKey.signature,
        elGamalPublicKey = FAKE_EL_GAMAL_PUBLIC_KEY,
        duchyCertificate = DUCHY_CERTIFICATE,
      )
    )
  }
}
