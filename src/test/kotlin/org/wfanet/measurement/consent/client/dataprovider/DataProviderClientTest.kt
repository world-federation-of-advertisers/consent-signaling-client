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
import com.google.protobuf.any
import com.google.protobuf.copy
import com.google.protobuf.kotlin.toByteString
import com.google.protobuf.kotlin.toByteStringUtf8
import com.google.protobuf.kotlin.unpack
import java.security.SecureRandom
import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXReason
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.EncryptedMessage
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.EventGroupKt.metadata
import org.wfanet.measurement.api.v2alpha.MeasurementKt.ResultKt.reach
import org.wfanet.measurement.api.v2alpha.MeasurementKt.result
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedMessage
import org.wfanet.measurement.api.v2alpha.copy
import org.wfanet.measurement.api.v2alpha.measurementSpec
import org.wfanet.measurement.api.v2alpha.randomSeed
import org.wfanet.measurement.api.v2alpha.requisitionSpec
import org.wfanet.measurement.api.v2alpha.signedMessage
import org.wfanet.measurement.common.HexString
import org.wfanet.measurement.common.crypto.HashAlgorithm
import org.wfanet.measurement.common.crypto.SignatureAlgorithm
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.tink.TinkPrivateKeyHandle
import org.wfanet.measurement.common.pack
import org.wfanet.measurement.consent.client.common.NonceMismatchException
import org.wfanet.measurement.consent.client.common.PublicKeyMismatchException
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toEncryptionPublicKey
import org.wfanet.measurement.consent.client.duchy.verifyRandomSeed
import org.wfanet.measurement.consent.client.measurementconsumer.decryptMetadata
import org.wfanet.measurement.consent.client.measurementconsumer.decryptResult
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
  measurementPublicKey = MEASUREMENT_PUBLIC_KEY.pack()
  nonceHashes += NONCE_HASH.bytes
}

private val FAKE_REQUISITION_SPEC = requisitionSpec {
  measurementPublicKey = MEASUREMENT_PUBLIC_KEY.pack()
  nonce = NONCE
}

private val FAKE_EL_GAMAL_PUBLIC_KEY = ElGamalPublicKey.getDefaultInstance()

private val FAKE_ENCRYPTION_PUBLIC_KEY = EncryptionPublicKey.getDefaultInstance()

private val FAKE_MEASUREMENT_RESULT = result { reach = reach { value = 100 } }

private val FAKE_EVENT_GROUP_METADATA = metadata {
  eventGroupMetadataDescriptor = "fake descriptor"
}

private const val RANDOM_SEED_LENGTH_IN_BYTES = 48
private val RANDOM_SEED = randomSeed {
  data = SecureRandom().generateSeed(RANDOM_SEED_LENGTH_IN_BYTES).toByteString()
}

@RunWith(JUnit4::class)
class DataProviderClientTest {
  @Test
  fun `verifyMeasurementSpec does not throw when signed MeasurementSpec is valid`() {
    val signingKeyHandle = MC_SIGNING_KEY
    val signedMeasurementSpec: SignedMessage =
      FAKE_MEASUREMENT_SPEC.serializeAndSign(signingKeyHandle, MC_SIGNING_ALGORITHM)

    verifyMeasurementSpec(signedMeasurementSpec, signingKeyHandle.certificate, MC_TRUSTED_ISSUER)
  }

  @Test
  fun `verifyMeasurementSpec throws when signature is invalid`() {
    val signingKeyHandle = MC_SIGNING_KEY
    val signedMeasurementSpec: SignedMessage =
      FAKE_MEASUREMENT_SPEC.serializeAndSign(signingKeyHandle, MC_SIGNING_ALGORITHM).copy {
        signature = signature.concat("garbage".toByteStringUtf8())
      }

    assertFailsWith<SignatureException> {
      verifyMeasurementSpec(signedMeasurementSpec, signingKeyHandle.certificate, MC_TRUSTED_ISSUER)
    }
  }

  @Test
  fun `verifyMeasurementSpec throws when certificate path is invalid`() {
    val signingKeyHandle = MC_SIGNING_KEY
    val signedMeasurementSpec: SignedMessage =
      FAKE_MEASUREMENT_SPEC.serializeAndSign(signingKeyHandle, MC_SIGNING_ALGORITHM)

    val exception =
      assertFailsWith<CertPathValidatorException> {
        verifyMeasurementSpec(
          signedMeasurementSpec,
          signingKeyHandle.certificate,
          EDP_TRUSTED_ISSUER,
        )
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun `decryptRequisitionSpec returns decrypted RequisitionSpec`() {
    // Encrypt a RequisitionSpec (as SignedMessage) using the Measurement Consumer Functions
    val signedRequisitionSpec: SignedMessage =
      signRequisitionSpec(FAKE_REQUISITION_SPEC, MC_SIGNING_KEY, MC_SIGNING_ALGORITHM)
    val encryptedRequisitionSpec: EncryptedMessage =
      encryptRequisitionSpec(
        signedRequisitionSpec = signedRequisitionSpec,
        measurementPublicKey = EDP_PUBLIC_KEY,
      )

    // Decrypt the SignedMessage RequisitionSpec
    val result: SignedMessage = decryptRequisitionSpec(encryptedRequisitionSpec, EDP_PRIVATE_KEY)

    val requisitionSpec: RequisitionSpec = result.message.unpack()
    assertThat(signedRequisitionSpec).isEqualTo(result)
    verifyRequisitionSpec(
      signedRequisitionSpec,
      requisitionSpec,
      FAKE_MEASUREMENT_SPEC,
      MC_SIGNING_KEY.certificate,
      MC_TRUSTED_ISSUER,
    )
  }

  @Test
  fun `verifyRequisitionSpec does not throw when signed RequisitionSpec is valid`() {
    val signedRequisitionSpec =
      signRequisitionSpec(FAKE_REQUISITION_SPEC, MC_SIGNING_KEY, MC_SIGNING_ALGORITHM)

    verifyRequisitionSpec(
      signedRequisitionSpec,
      FAKE_REQUISITION_SPEC,
      FAKE_MEASUREMENT_SPEC,
      MC_SIGNING_KEY.certificate,
      MC_TRUSTED_ISSUER,
    )
  }

  @Test
  fun `verifyRequisitionSpec does not throw when legacy RequisitionSpec is valid`() {
    val requisitionSpec =
      FAKE_REQUISITION_SPEC.copy {
        @Suppress("DEPRECATION") // For legacy resources.
        serializedMeasurementPublicKey = measurementPublicKey.value
        clearMeasurementPublicKey()
      }
    val measurementSpec =
      FAKE_MEASUREMENT_SPEC.copy {
        @Suppress("DEPRECATION") // For legacy resources.
        serializedMeasurementPublicKey = measurementPublicKey.value
        clearMeasurementPublicKey()
      }
    val signedRequisitionSpec =
      signRequisitionSpec(requisitionSpec, MC_SIGNING_KEY, MC_SIGNING_ALGORITHM)

    verifyRequisitionSpec(
      signedRequisitionSpec,
      requisitionSpec,
      measurementSpec,
      MC_SIGNING_KEY.certificate,
      MC_TRUSTED_ISSUER,
    )
  }

  @Test
  fun `verifyRequisitionSpec throws when nonce mismatches`() {
    val signedRequisitionSpec =
      signRequisitionSpec(FAKE_REQUISITION_SPEC, MC_SIGNING_KEY, MC_SIGNING_ALGORITHM)
    val measurementSpec = FAKE_MEASUREMENT_SPEC.copy { nonceHashes.clear() }

    assertFailsWith<NonceMismatchException> {
      verifyRequisitionSpec(
        signedRequisitionSpec,
        FAKE_REQUISITION_SPEC,
        measurementSpec,
        MC_SIGNING_KEY.certificate,
        MC_TRUSTED_ISSUER,
      )
    }
  }

  @Test
  fun `verifyRequisitionSpec throws when public key mismatches`() {
    val signedRequisitionSpec =
      signRequisitionSpec(FAKE_REQUISITION_SPEC, MC_SIGNING_KEY, MC_SIGNING_ALGORITHM)
    val measurementSpec =
      FAKE_MEASUREMENT_SPEC.copy {
        measurementPublicKey =
          measurementPublicKey.copy { value = value.concat("garbage".toByteStringUtf8()) }
      }

    assertFailsWith<PublicKeyMismatchException> {
      verifyRequisitionSpec(
        signedRequisitionSpec,
        FAKE_REQUISITION_SPEC,
        measurementSpec,
        MC_SIGNING_KEY.certificate,
        MC_TRUSTED_ISSUER,
      )
    }
  }

  @Test
  fun `verifyRequisitionSpec throws when legacy public key mismatches`() {
    val requisitionSpec =
      FAKE_REQUISITION_SPEC.copy {
        @Suppress("DEPRECATION") // For legacy resources.
        serializedMeasurementPublicKey = measurementPublicKey.value
        clearMeasurementPublicKey()
      }
    val measurementSpec =
      FAKE_MEASUREMENT_SPEC.copy {
        @Suppress("DEPRECATION") // For legacy resources.
        serializedMeasurementPublicKey =
          measurementPublicKey.value.concat("garbage".toByteStringUtf8())
        clearMeasurementPublicKey()
      }
    val signedRequisitionSpec =
      signRequisitionSpec(requisitionSpec, MC_SIGNING_KEY, MC_SIGNING_ALGORITHM)

    assertFailsWith<PublicKeyMismatchException> {
      verifyRequisitionSpec(
        signedRequisitionSpec,
        FAKE_REQUISITION_SPEC,
        measurementSpec,
        MC_SIGNING_KEY.certificate,
        MC_TRUSTED_ISSUER,
      )
    }
  }

  @Test
  fun `verifyRequisitionSpec throws when signature is invalid`() {
    val signedRequisitionSpec =
      signRequisitionSpec(FAKE_REQUISITION_SPEC, MC_SIGNING_KEY, MC_SIGNING_ALGORITHM).copy {
        signature = signature.concat("garbage".toByteStringUtf8())
      }

    assertFailsWith<SignatureException> {
      verifyRequisitionSpec(
        signedRequisitionSpec,
        FAKE_REQUISITION_SPEC,
        FAKE_MEASUREMENT_SPEC,
        MC_SIGNING_KEY.certificate,
        MC_TRUSTED_ISSUER,
      )
    }
  }

  @Test
  fun `verifyRequisitionSpec throws certificate path is invalid`() {
    val signedRequisitionSpec =
      signRequisitionSpec(FAKE_REQUISITION_SPEC, MC_SIGNING_KEY, MC_SIGNING_ALGORITHM)

    val exception =
      assertFailsWith<CertPathValidatorException> {
        verifyRequisitionSpec(
          signedRequisitionSpec,
          FAKE_REQUISITION_SPEC,
          FAKE_MEASUREMENT_SPEC,
          MC_SIGNING_KEY.certificate,
          EDP_TRUSTED_ISSUER,
        )
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun `verifyElGamalPublicKey does not throw when signed key is valid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedMessage =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM)

    verifyElGamalPublicKey(
      signedElGamalPublicKey,
      signingKeyHandle.certificate,
      DUCHY_TRUSTED_ISSUER,
    )
  }

  @Test
  fun `verifyElGamalPublicKey throws when signature is invalid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedMessage =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM).copy {
        signature = signature.concat("garbage".toByteStringUtf8())
      }

    assertFailsWith<SignatureException> {
      verifyElGamalPublicKey(
        signedElGamalPublicKey,
        signingKeyHandle.certificate,
        DUCHY_TRUSTED_ISSUER,
      )
    }
  }

  @Test
  fun `verifyElGamalPublicKey throws when certificate path is invalid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedMessage =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM)

    val exception =
      assertFailsWith<CertPathValidatorException> {
        verifyElGamalPublicKey(
          signedElGamalPublicKey,
          signingKeyHandle.certificate,
          MC_TRUSTED_ISSUER,
        )
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun `signResult returns valid signature`() {
    val signedResult = signResult(FAKE_MEASUREMENT_RESULT, EDP_SIGNING_KEY, EDP_SIGNING_ALGORITHM)

    verifyResult(signedResult, EDP_SIGNING_KEY.certificate, EDP_TRUSTED_ISSUER)
  }

  @Test
  fun `encryptMetadata returns encrypted Metadata`() {
    val encryptedMetadata =
      encryptMetadata(
        metadata = FAKE_EVENT_GROUP_METADATA,
        measurementConsumerPublicKey = MC_PUBLIC_KEY,
      )

    val metadata = decryptMetadata(encryptedMetadata, MC_PRIVATE_KEY)
    assertThat(metadata).isEqualTo(FAKE_EVENT_GROUP_METADATA)
  }

  @Test
  fun `encryptResult returns encrypted Result`() {
    val signedResult: SignedMessage =
      signResult(FAKE_MEASUREMENT_RESULT, EDP_SIGNING_KEY, EDP_SIGNING_ALGORITHM)

    val encryptedResult: EncryptedMessage = encryptResult(signedResult, MC_PUBLIC_KEY)

    val decryptedResult = decryptResult(encryptedResult, MC_PRIVATE_KEY)
    assertThat(decryptedResult).isEqualTo(signedResult)
  }

  @Test
  fun `signRandomSeed returns signed RandomSeed`() {
    val signedRandomSeed = signRandomSeed(RANDOM_SEED, EDP_SIGNING_KEY, EDP_SIGNING_ALGORITHM)

    verifyRandomSeed(signedRandomSeed, EDP_SIGNING_KEY.certificate, EDP_TRUSTED_ISSUER)
  }

  @Test
  fun `encryptRandomSeed returns encrypted data`() {
    val duchyPrivateKey = TinkPrivateKeyHandle.generateHpke()
    val duchyPublicKey = duchyPrivateKey.publicKey.toEncryptionPublicKey()
    val signedRandomSeed = signedMessage {
      message = any { value = ByteString.copyFromUtf8("a random seed") }
      signature = ByteString.copyFromUtf8("a random seed signature")
    }

    val encryptedSignedRandomSeed = encryptRandomSeed(signedRandomSeed, duchyPublicKey)

    val decryptedSignedRandomSeed =
      SignedMessage.parseFrom(duchyPrivateKey.hybridDecrypt(encryptedSignedRandomSeed.ciphertext))
    assertThat(decryptedSignedRandomSeed).isEqualTo(signedRandomSeed)
  }

  @Test
  fun `verifyEncryptionPublicKey does not throw when signature is valid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedEncryptionPublicKey: SignedMessage =
      FAKE_ENCRYPTION_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM)

    verifyEncryptionPublicKey(
      signedEncryptionPublicKey,
      signingKeyHandle.certificate,
      DUCHY_TRUSTED_ISSUER,
    )
  }

  @Test
  fun `verifyEncryptionPublicKey throws when signature is invalid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedEncryptionPublicKey: SignedMessage =
      FAKE_ENCRYPTION_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM).copy {
        signature = signature.concat("garbage".toByteStringUtf8())
      }

    assertFailsWith<SignatureException> {
      verifyEncryptionPublicKey(
        signedEncryptionPublicKey,
        signingKeyHandle.certificate,
        DUCHY_TRUSTED_ISSUER,
      )
    }
  }

  @Test
  fun `verifyEncryptionPublicKey throws when certificate path is invalid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedEncryptionPublicKey: SignedMessage =
      FAKE_ENCRYPTION_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM)

    val exception =
      assertFailsWith<CertPathValidatorException> {
        verifyEncryptionPublicKey(
          signedEncryptionPublicKey,
          signingKeyHandle.certificate,
          MC_TRUSTED_ISSUER,
        )
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  companion object {
    private val MC_SIGNING_KEY = readSigningKeyHandle(MC_1_CERT_PEM_FILE, MC_1_KEY_FILE)
    private val MC_SIGNING_ALGORITHM =
      SignatureAlgorithm.fromKeyAndHashAlgorithm(
        MC_SIGNING_KEY.certificate.publicKey,
        HashAlgorithm.SHA256,
      )!!
    private val MC_PRIVATE_KEY = TinkPrivateKeyHandle.generateEcies()
    private val MC_PUBLIC_KEY = MC_PRIVATE_KEY.publicKey.toEncryptionPublicKey()
    private val MC_TRUSTED_ISSUER = readCertificate(MC_1_ROOT_CERT_PEM_FILE)

    private val DUCHY_SIGNING_KEY =
      readSigningKeyHandle(DUCHY_1_NON_AGG_CERT_PEM_FILE, DUCHY_1_NON_AGG_KEY_FILE)
    private val DUCHY_SIGNING_ALGORITHM =
      SignatureAlgorithm.fromKeyAndHashAlgorithm(
        DUCHY_SIGNING_KEY.certificate.publicKey,
        HashAlgorithm.SHA256,
      )!!
    private val DUCHY_TRUSTED_ISSUER = readCertificate(DUCHY_1_NON_AGG_ROOT_CERT_PEM_FILE)

    private val EDP_SIGNING_KEY = readSigningKeyHandle(EDP_1_CERT_PEM_FILE, EDP_1_KEY_FILE)
    private val EDP_SIGNING_ALGORITHM =
      SignatureAlgorithm.fromKeyAndHashAlgorithm(
        EDP_SIGNING_KEY.certificate.publicKey,
        HashAlgorithm.SHA256,
      )!!
    private val EDP_TRUSTED_ISSUER = readCertificate(EDP_1_ROOT_CERT_PEM_FILE)
    private val EDP_PRIVATE_KEY = TinkPrivateKeyHandle.generateEcies()
    private val EDP_PUBLIC_KEY = EDP_PRIVATE_KEY.publicKey.toEncryptionPublicKey()
  }
}
