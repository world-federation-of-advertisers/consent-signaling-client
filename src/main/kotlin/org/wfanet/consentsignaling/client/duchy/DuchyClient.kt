package org.wfanet.consentsignaling.client.duchy

import com.google.protobuf.ByteString
import org.wfanet.consentsignaling.client.hybridCryptor
import org.wfanet.consentsignaling.client.signer
import org.wfanet.consentsignaling.crypto.hash.generateDataProviderListHash
import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.system.v1alpha.Computation
import org.wfanet.measurement.system.v1alpha.Requisition

/**
 * Verifies the EDP Participation using the Duchy's Computation and Requisition against the
 * DataProviderCertificate
 */
fun verifyEdpParticipationSignature(
  computation: Computation,
  requisition: Requisition,
  dataProviderCertificate: Certificate
): Boolean {
  // TODO: Verify Data Provider Certificate (is from root authority)

  // Get the Signature...
  val signature = requisition.dataProviderParticipationSignature
  // Generate the Data Provider List Hash
  val dataProviderListHash: ByteString =
    generateDataProviderListHash(computation.dataProviderList, computation.dataProviderListSalt)
  // Calculate the Requisition Fingerprint
  val requisitionFingerprint =
    ByteString.copyFrom(
      requisition
        .requisitionSpecHash
        .toByteArray()
        .plus(dataProviderListHash.toByteArray())
        .plus(computation.measurementSpec.toByteArray())
    )

  // TODO Verify the EdpParticipantSignature has not been previously reused to protect against
  // replay attacks

  return signer.verify(dataProviderCertificate, signature.toByteArray(), requisitionFingerprint)
}

/**
 * Sign and encrypts the Result into a serialized SignedData ProtoBuf The aggregator certificate is
 * required to determine the algorithm type of the signature
 */
fun signAndEncryptResult(
  result: Measurement.Result,
  duchyPrivateKeyHandle: PrivateKeyHandle,
  aggregatorCertificate: Certificate,
  measurementPublicKey: EncryptionPublicKey
): ByteArray {
  // Sign the result with the private key
  val signature = signer.sign(aggregatorCertificate, duchyPrivateKeyHandle, result.toByteString())

  // Create the SignedData
  val signedData =
    SignedData.newBuilder()
      .also {
        it.data = result.toByteString()
        it.signature = ByteString.copyFrom(signature)
      }
      .build()
  // Encrypt the SignedData
  return hybridCryptor.encrypt(measurementPublicKey, signedData.toByteArray())
}
