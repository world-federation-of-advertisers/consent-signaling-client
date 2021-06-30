package org.wfanet.consentsignaling.client.duchy

import com.google.protobuf.ByteString
import org.wfanet.consentsignaling.client.crypto
import org.wfanet.consentsignaling.client.signage
import org.wfanet.consentsignaling.common.generateDataProviderListHash
import org.wfanet.consentsignaling.crypto.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.Measurement
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.system.v1alpha.Computation
import org.wfanet.measurement.system.v1alpha.Requisition

/**
 * Verifies the EDP Participation using the Duchies' Computation and Requisition against the
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
  val dataProviderListHash: ByteArray = generateDataProviderListHash(
    computation.dataProviderList.toByteArray(),
    computation.dataProviderListSalt.toByteArray()
  )
  // Calculate the Requisition Fingerprint
  val requisitionFingerprint =
    requisition.requisitionSpecHash.toByteArray()
      .plus(dataProviderListHash)
      .plus(computation.measurementSpec.toByteArray())

  // TODO Verify the EdpParticipantSignature has not been previously reused to protect against replay attacks

  return signage.verify(dataProviderCertificate, signature.toByteArray(), requisitionFingerprint)
}

/**
 * Sign and encrypts the Result into a serialized SignedData ProtoBuf
 * The aggregator certificate is required to determine the algorithm type of the signature
 */
fun signAndEncryptResult(
  result: Measurement.Result,
  duchyPrivateKeyHandle: PrivateKeyHandle,
  aggregatorCertificate: Certificate,
  measurementPublicKey: EncryptionPublicKey
): ByteArray {
  // Sign the result with the private key
  val signature = signage.sign(aggregatorCertificate, duchyPrivateKeyHandle, result.toByteArray())

  // Create the SignedData
  val signedData = SignedData.newBuilder().also {
    it.data = result.toByteString()
    it.signature = ByteString.copyFrom(signature)
  }.build()
  // Encrypt the SignedData
  return crypto.encrypt(measurementPublicKey, signedData.toByteArray())
}
