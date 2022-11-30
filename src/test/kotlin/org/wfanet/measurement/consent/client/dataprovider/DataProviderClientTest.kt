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
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.EventGroupKt.metadata
import org.wfanet.measurement.api.v2alpha.MeasurementKt.ResultKt.reach
import org.wfanet.measurement.api.v2alpha.MeasurementKt.result
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.api.v2alpha.measurementSpec
import org.wfanet.measurement.api.v2alpha.requisitionSpec
import org.wfanet.measurement.common.HexString
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.tink.TinkPrivateKeyHandle
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toEncryptionPublicKey
import org.wfanet.measurement.consent.client.measurementconsumer.decryptMetadata
import org.wfanet.measurement.consent.client.measurementconsumer.encryptRequisitionSpec
import org.wfanet.measurement.consent.client.measurementconsumer.signRequisitionSpec
import org.wfanet.measurement.consent.client.measurementconsumer.verifyResult
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_KEY_FILE
import org.wfanet.measurement.consent.testing.EDP_1_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.MC_1_KEY_FILE
import org.wfanet.measurement.consent.testing.MC_1_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.readSigningKeyHandle

private const val NONCE = -7452112597811743614 // Hex: 9894C7134537B482
private val NONCE_HASH =
  HexString("A4EA9C2984AE1D0F7D0B026B0BB41C136FC0767E29DF40951CFE019B7D9F1CE1")
private val MEASUREMENT_PUBLIC_KEY =
  EncryptionPublicKey.newBuilder()
    .apply { data = ByteString.copyFromUtf8("some-public-key") }
    .build()

private val FAKE_MEASUREMENT_SPEC = measurementSpec {
  measurementPublicKey = MEASUREMENT_PUBLIC_KEY.toByteString()
  nonceHashes += NONCE_HASH.bytes
}

private val FAKE_REQUISITION_SPEC = requisitionSpec {
  measurementPublicKey = MEASUREMENT_PUBLIC_KEY.toByteString()
  nonce = NONCE
}

private val FAKE_EL_GAMAL_PUBLIC_KEY = ElGamalPublicKey.getDefaultInstance()

private val FAKE_MEASUREMENT_RESULT = result { reach = reach { value = 100 } }

private val FAKE_EVENT_GROUP_METADATA = metadata {
  eventGroupMetadataDescriptor = "fake descriptor"
}

@RunWith(JUnit4::class)
class DataProviderClientTest {
  @Test
  fun `verifyMeasurementSpec does not throw when signed MeasurementSpec is valid`() = runBlocking {
    val signingKeyHandle = MC_SIGNING_KEY
    val signedMeasurementSpec: SignedData = FAKE_MEASUREMENT_SPEC.serializeAndSign(signingKeyHandle)

    verifyMeasurementSpec(signedMeasurementSpec, signingKeyHandle.certificate, MC_TRUSTED_ISSUER)
  }

  @Test
  fun `decryptRequisitionSpec returns decrypted RequisitionSpec`() = runBlocking {
    // Encrypt a RequisitionSpec (as SignedData) using the Measurement Consumer Functions
    val signedRequisitionSpec = signRequisitionSpec(FAKE_REQUISITION_SPEC, MC_SIGNING_KEY)
    val encryptedRequisitionSpec =
      encryptRequisitionSpec(
        signedRequisitionSpec = signedRequisitionSpec,
        measurementPublicKey = EDP_PUBLIC_KEY
      )

    // Decrypt the SignedData RequisitionSpec
    val decryptedSignedDataRequisitionSpec: SignedData =
      decryptRequisitionSpec(encryptedRequisitionSpec, EDP_PRIVATE_KEY)
    val decryptedRequisitionSpec =
      RequisitionSpec.parseFrom(decryptedSignedDataRequisitionSpec.data)

    assertThat(signedRequisitionSpec).isEqualTo(decryptedSignedDataRequisitionSpec)
    verifyRequisitionSpec(
      signedRequisitionSpec,
      decryptedRequisitionSpec,
      FAKE_MEASUREMENT_SPEC,
      MC_SIGNING_KEY.certificate,
      MC_TRUSTED_ISSUER
    )
  }

  @Test
  fun `verifyRequisitionSpec does not throw when signed RequisitionSpec is valid`() = runBlocking {
    val signedRequisitionSpec = signRequisitionSpec(FAKE_REQUISITION_SPEC, MC_SIGNING_KEY)

    verifyRequisitionSpec(
      signedRequisitionSpec,
      FAKE_REQUISITION_SPEC,
      FAKE_MEASUREMENT_SPEC,
      MC_SIGNING_KEY.certificate,
      MC_TRUSTED_ISSUER
    )
  }

  @Test
  fun `verifiesElgamalPublicKey does not throw exception when signature is valid`() = runBlocking {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedData =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle)

    verifyElGamalPublicKey(
      signedElGamalPublicKey,
      signingKeyHandle.certificate,
      DUCHY_TRUSTED_ISSUER
    )
  }

  @Test
  fun `signResult returns valid signature`() = runBlocking {
    val signedResult =
      signResult(
        result = FAKE_MEASUREMENT_RESULT,
        dataProviderSigningKey = EDP_SIGNING_KEY,
      )

    verifyResult(signedResult, EDP_SIGNING_KEY.certificate, EDP_TRUSTED_ISSUER)
  }

  @Test
  fun `encryptMetadata returns encrypted Metadata`() = runBlocking {
    val encryptedMetadata =
      encryptMetadata(
        metadata = FAKE_EVENT_GROUP_METADATA,
        measurementConsumerPublicKey = MC_PUBLIC_KEY
      )

    val metadata = decryptMetadata(encryptedMetadata, MC_PRIVATE_KEY)
    assertThat(metadata).isEqualTo(FAKE_EVENT_GROUP_METADATA)
  }

  companion object {
    private val MC_SIGNING_KEY = readSigningKeyHandle(MC_1_CERT_PEM_FILE, MC_1_KEY_FILE)
    private val MC_PRIVATE_KEY = TinkPrivateKeyHandle.generateEcies()
    private val MC_PUBLIC_KEY = MC_PRIVATE_KEY.publicKey.toEncryptionPublicKey()
    private val MC_TRUSTED_ISSUER = readCertificate(MC_1_ROOT_CERT_PEM_FILE)

    private val DUCHY_SIGNING_KEY =
      readSigningKeyHandle(DUCHY_1_NON_AGG_CERT_PEM_FILE, DUCHY_1_NON_AGG_KEY_FILE)
    private val DUCHY_TRUSTED_ISSUER = readCertificate(DUCHY_1_NON_AGG_ROOT_CERT_PEM_FILE)

    private val EDP_SIGNING_KEY = readSigningKeyHandle(EDP_1_CERT_PEM_FILE, EDP_1_KEY_FILE)
    private val EDP_TRUSTED_ISSUER = readCertificate(EDP_1_ROOT_CERT_PEM_FILE)
    private val EDP_PRIVATE_KEY = TinkPrivateKeyHandle.generateEcies()
    private val EDP_PUBLIC_KEY = EDP_PRIVATE_KEY.publicKey.toEncryptionPublicKey()
  }
}
