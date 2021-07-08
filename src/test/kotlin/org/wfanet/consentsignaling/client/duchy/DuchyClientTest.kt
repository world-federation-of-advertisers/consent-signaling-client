package org.wfanet.consentsignaling.client.duchy

import com.google.protobuf.ByteString
import kotlin.test.assertTrue
import org.junit.Test
import org.wfanet.consentsignaling.client.hybridCryptor
import org.wfanet.consentsignaling.client.signage
import org.wfanet.consentsignaling.crypto.NoHybridCryptor
import org.wfanet.consentsignaling.crypto.keystore.InMemoryKeyStore
import org.wfanet.consentsignaling.crypto.signage.NoSignage
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
    signage = NoSignage()
    hybridCryptor = NoHybridCryptor()

    /**
     * Items already known to the duchy
     */
    val computation = Computation.newBuilder().also {
      it.dataProviderList // TODO
      it.dataProviderListSalt // TODO
      it.measurementSpec = MeasurementSpec.newBuilder().build().toByteString()
    }.build()

    val requisition = Requisition.newBuilder().also {
      it.dataProviderCertificate // TODO
      it.dataProviderParticipationSignature // TODO
    }.build()

    val dataProviderCertificate = Certificate.newBuilder().also {
      it.x509Der // TODO
    }.build()

    /**
     * Verify EDP Signature
     */
    assertTrue(verifyEdpParticipationSignature(computation, requisition, dataProviderCertificate))
  }

  @Test
  fun `duchy sign and encrypt result`() {
    signage = NoSignage()
    hybridCryptor = NoHybridCryptor()

    /**
     * Items already setup in the aggregator duchy
     */
    // Duchy Private Key Storage
    val duchyPrivateKeyID = "duchyPrivateKeyID"
    val privateKeyBytes = ByteString.copyFrom("TODO".toByteArray())
    val keystore = InMemoryKeyStore()
    keystore.storePrivateKeyDER(duchyPrivateKeyID, privateKeyBytes)
    // Duchy/Aggregator Certificate
    val aggregatorCertificate = Certificate.newBuilder().also {
      it.x509Der // TODO
    }.build()
    val measurementConsumerPublicKey = EncryptionPublicKey.newBuilder().also {
      it.type // TODO
      it.publicKeyInfo // TODO
    }.build()

    /**
     * Items already known to the duchy/aggregator
     */
    val result = Measurement.Result.newBuilder().also {
      // TODO
    }.build()

    /**
     * Sign and Encrypt
     */
    val duchyPrivateKeyHandle = keystore.getPrivateKeyHandle(duchyPrivateKeyID)
    Measurement.newBuilder().also {
      it.encryptedResult = ByteString.copyFrom(
        signAndEncryptResult(
          result,
          duchyPrivateKeyHandle,
          aggregatorCertificate,
          measurementConsumerPublicKey
        )
      )
    }
  }
}
