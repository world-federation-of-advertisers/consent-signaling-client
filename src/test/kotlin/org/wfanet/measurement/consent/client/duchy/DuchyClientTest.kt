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
import com.google.protobuf.any
import com.google.protobuf.kotlin.toByteString
import com.google.protobuf.kotlin.toByteStringUtf8
import java.security.SecureRandom
import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import java.security.cert.PKIXReason
import java.util.Random
import kotlin.test.assertFailsWith
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.ElGamalPublicKey
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement.Result as MeasurementResult
import org.wfanet.measurement.api.v2alpha.RequisitionSpec
import org.wfanet.measurement.api.v2alpha.SignedMessage
import org.wfanet.measurement.api.v2alpha.copy
import org.wfanet.measurement.api.v2alpha.encryptedMessage
import org.wfanet.measurement.api.v2alpha.measurementSpec
import org.wfanet.measurement.api.v2alpha.randomSeed
import org.wfanet.measurement.api.v2alpha.requisition
import org.wfanet.measurement.api.v2alpha.signedMessage
import org.wfanet.measurement.common.HexString
import org.wfanet.measurement.common.ProtoReflection
import org.wfanet.measurement.common.crypto.HashAlgorithm
import org.wfanet.measurement.common.crypto.Hashing
import org.wfanet.measurement.common.crypto.SignatureAlgorithm
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.tink.TinkPrivateKeyHandle
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.consent.client.common.serializeAndSign
import org.wfanet.measurement.consent.client.common.toEncryptionPublicKey
import org.wfanet.measurement.consent.client.dataprovider.computeRequisitionFingerprint
import org.wfanet.measurement.consent.client.dataprovider.encryptRandomSeed
import org.wfanet.measurement.consent.client.dataprovider.verifyEncryptionPublicKey
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.DUCHY_1_NON_AGG_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.DUCHY_AGG_KEY_FILE
import org.wfanet.measurement.consent.testing.EDP_1_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.EDP_1_KEY_FILE
import org.wfanet.measurement.consent.testing.EDP_1_ROOT_CERT_PEM_FILE
import org.wfanet.measurement.consent.testing.readSigningKeyHandle

private const val NONCE = -7452112597811743614L // Hex: 9894C7134537B482
private val NONCE_HASH =
  HexString("A4EA9C2984AE1D0F7D0B026B0BB41C136FC0767E29DF40951CFE019B7D9F1CE1")
private const val NONCE_2 = -3060866405677570814L // Hex: D5859E38A0A96502
private val NONCE_2_HASH =
  HexString("45FEAA185D434E0EB4747F547F0918AA5B8403DBBD7F90D6F0D8C536E2D620D7")

private val MEASUREMENT_SPEC = measurementSpec { nonceHashes += NONCE_HASH.bytes }

private val FAKE_EL_GAMAL_PUBLIC_KEY = ElGamalPublicKey.getDefaultInstance()

private val FAKE_ENCRYPTION_PUBLIC_KEY = EncryptionPublicKey.getDefaultInstance()

private const val RANDOM_SEED_LENGTH_IN_BYTES = 48
private val RANDOM_SEED = randomSeed {
  data = SecureRandom().generateSeed(RANDOM_SEED_LENGTH_IN_BYTES).toByteString()
}

@RunWith(JUnit4::class)
class DuchyClientTest {
  @Test
  fun `computeRequisitionFingerprint returns Requisition fingerprint`() {
    // Compute what Duchy would store from Kingdom data.
    val encryptedRequisitionSpec = encryptedMessage {
      ciphertext = "Encrypted RequisitionSpec".toByteStringUtf8()
      typeUrl = ProtoReflection.getTypeUrl(RequisitionSpec.getDescriptor())
    }
    val requisitionSpecHash = Hashing.hashSha256(encryptedRequisitionSpec.ciphertext)
    val serializedMeasurementSpec = MEASUREMENT_SPEC.toByteString()

    val requisitionFingerprint =
      computeRequisitionFingerprint(serializedMeasurementSpec, requisitionSpecHash)

    // Verify that fingerprint matches the same one that would be computed by Data Provider.
    assertThat(requisitionFingerprint)
      .isEqualTo(
        computeRequisitionFingerprint(
          requisition {
            measurementSpec = signedMessage {
              message = any {
                value = serializedMeasurementSpec
                typeUrl = ProtoReflection.getTypeUrl(MEASUREMENT_SPEC.descriptorForType)
              }
            }
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
          nonce = NONCE,
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
          nonce = 404L,
        )
      )
      .isFalse()
  }

  @Test
  fun `verifyDataProviderParticipation returns true when verified`() {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE, NONCE_2),
        )
      )
      .isTrue()
  }

  @Test
  fun `verifyDataProviderParticipation returns false when missing a nonce`() {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE),
        )
      )
      .isFalse()
  }

  @Test
  fun `verifyDataProviderParticipation returns false when nonce mismatches hash`() {
    assertThat(
        verifyDataProviderParticipation(
          MEASUREMENT_SPEC.copy { nonceHashes += NONCE_2_HASH.bytes },
          listOf(NONCE, 404L),
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
      signResult(someMeasurementResult, AGGREGATOR_SIGNING_KEY, AGGREGATOR_SIGNING_ALGORITHM)
    assertThat(
        AGGREGATOR_SIGNING_KEY.certificate.verifySignature(
          AGGREGATOR_SIGNING_ALGORITHM,
          signedResult.message.value,
          signedResult.signature,
        )
      )
      .isTrue()
  }

  @Test
  fun `duchy encrypt result`() {
    val measurementEncryptionKey = TinkPrivateKeyHandle.generateEcies()
    val measurementPublicKey = measurementEncryptionKey.publicKey.toEncryptionPublicKey()
    val signedMeasurementResult = signedMessage {
      message = any { value = ByteString.copyFromUtf8("some measurement result") }
      signature = ByteString.copyFromUtf8("some measurement result signature")
    }

    val encryptedSignedResult =
      encryptResult(
        signedResult = signedMeasurementResult,
        measurementPublicKey = measurementPublicKey,
      )

    val decryptedSignedResult =
      SignedMessage.parseFrom(
        measurementEncryptionKey.hybridDecrypt(encryptedSignedResult.ciphertext)
      )
    assertThat(decryptedSignedResult).isEqualTo(signedMeasurementResult)
  }

  @Test
  fun `verifyElGamalPublicKey does not throw exception when signature is valid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedMessage =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM)

    verifyElGamalPublicKey(
      signedElGamalPublicKey.message.value,
      signedElGamalPublicKey.signature,
      DUCHY_SIGNING_ALGORITHM,
      signingKeyHandle.certificate,
      DUCHY_TRUSTED_ISSUER,
    )
  }

  @Test
  fun `verifyElGamalPublicKey throws when certificate path is invalid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedMessage =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM)
    val incorrectIssuer = DUCHY_SIGNING_KEY.certificate

    val exception =
      assertFailsWith<CertPathValidatorException> {
        verifyElGamalPublicKey(
          signedElGamalPublicKey.message.value,
          signedElGamalPublicKey.signature,
          DUCHY_SIGNING_ALGORITHM,
          signingKeyHandle.certificate,
          incorrectIssuer,
        )
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun `verifyElGamalPublicKey throws when signature is invalid`() {
    val signingKeyHandle = DUCHY_SIGNING_KEY
    val signedElGamalPublicKey: SignedMessage =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle, DUCHY_SIGNING_ALGORITHM)
    val badSignature: ByteString =
      signedElGamalPublicKey.signature.concat("garbage".toByteStringUtf8())

    assertFailsWith<SignatureException> {
      verifyElGamalPublicKey(
        signedElGamalPublicKey.message.value,
        badSignature,
        DUCHY_SIGNING_ALGORITHM,
        signingKeyHandle.certificate,
        DUCHY_TRUSTED_ISSUER,
      )
    }
  }

  @Test
  fun `decryptRandomSeed returns the RandomSeed`() {
    val duchyPrivateKey = TinkPrivateKeyHandle.generateHpke()
    val duchyPublicKey = duchyPrivateKey.publicKey.toEncryptionPublicKey()
    val signedRandomSeed = signedMessage {
      message = any { value = ByteString.copyFromUtf8("a random seed") }
      signature = ByteString.copyFromUtf8("a random seed signature")
    }
    val encryptedSignedRandomSeed = encryptRandomSeed(signedRandomSeed, duchyPublicKey)

    val decryptedSignedRandomSeed = decryptRandomSeed(encryptedSignedRandomSeed, duchyPrivateKey)

    assertThat(decryptedSignedRandomSeed).isEqualTo(signedRandomSeed)
  }

  @Test
  fun `verifyRandomSeed verifies a signed randomSeed`() {
    val signingKeyHandle = EDP_SIGNING_KEY
    val signedRandomSeed = RANDOM_SEED.serializeAndSign(signingKeyHandle, EDP_SIGNING_ALGORITHM)

    verifyRandomSeed(signedRandomSeed, signingKeyHandle.certificate, EDP_TRUSTED_ISSUER)
  }

  @Test
  fun `verifyRandomSeed throws when certificate path is invalid`() {
    val signingKeyHandle = EDP_SIGNING_KEY
    val signedRandomSeed: SignedMessage =
      RANDOM_SEED.serializeAndSign(signingKeyHandle, EDP_SIGNING_ALGORITHM)
    val incorrectIssuer = DUCHY_SIGNING_KEY.certificate

    val exception =
      assertFailsWith<CertPathValidatorException> {
        verifyRandomSeed(signedRandomSeed, signingKeyHandle.certificate, incorrectIssuer)
      }
    assertThat(exception.reason).isEqualTo(PKIXReason.NO_TRUST_ANCHOR)
  }

  @Test
  fun `verifyRandomSeed throws when signature is invalid`() {
    val signingKeyHandle = EDP_SIGNING_KEY
    val signedRandomSeed: SignedMessage =
      FAKE_EL_GAMAL_PUBLIC_KEY.serializeAndSign(signingKeyHandle, EDP_SIGNING_ALGORITHM)
    val badSignature =
      signedRandomSeed.copy { signature = signature.concat("garbage".toByteStringUtf8()) }

    assertFailsWith<SignatureException> {
      verifyRandomSeed(badSignature, signingKeyHandle.certificate, EDP_TRUSTED_ISSUER)
    }
  }

  @Test
  fun `signEncryptionPublicKey returns signed message`() {
    val signedEncryptionPublicKey =
      signEncryptionPublicKey(
        FAKE_ENCRYPTION_PUBLIC_KEY,
        DUCHY_SIGNING_KEY,
        DUCHY_SIGNING_ALGORITHM,
      )

    verifyEncryptionPublicKey(
      signedEncryptionPublicKey,
      DUCHY_SIGNING_KEY.certificate,
      DUCHY_TRUSTED_ISSUER,
    )
  }

  companion object {
    private val AGGREGATOR_SIGNING_KEY =
      readSigningKeyHandle(DUCHY_AGG_CERT_PEM_FILE, DUCHY_AGG_KEY_FILE)
    private val AGGREGATOR_SIGNING_ALGORITHM =
      SignatureAlgorithm.fromKeyAndHashAlgorithm(
        AGGREGATOR_SIGNING_KEY.certificate.publicKey,
        HashAlgorithm.SHA256,
      )!!

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
