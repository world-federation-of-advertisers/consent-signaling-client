/*
 * Copyright 2021 The Cross-Media Measurement Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wfanet.measurement.consent.client.common

import com.google.protobuf.Message
import java.security.SignatureException
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.SignedMessage
import org.wfanet.measurement.api.v2alpha.signedMessage
import org.wfanet.measurement.common.crypto.SignatureAlgorithm
import org.wfanet.measurement.common.crypto.SigningKeyHandle
import org.wfanet.measurement.common.crypto.verifySignature
import org.wfanet.measurement.common.pack

/** Serializes this [Message] and signs it using [signingKey]. */
fun Message.serializeAndSign(
  signingKey: SigningKeyHandle,
  algorithm: SignatureAlgorithm = signingKey.defaultAlgorithm
): SignedMessage {
  return signedMessage {
    message = pack()
    signature = signingKey.sign(algorithm, message.value)
    signatureAlgorithmOid = algorithm.oid

    // TODO(world-federation-of-advertisers/cross-media-measurement#1301): Stop setting this field.
    data = message.value
  }
}

/**
 * Verifies the [signature][SignedMessage.getSignature] against the [data][SignedMessage.getData].
 *
 * @throws SignatureException if the signature is invalid
 */
@Throws(SignatureException::class)
fun X509Certificate.verifySignedMessage(signedMessage: SignedMessage) {
  val oid = signedMessage.signatureAlgorithmOid.ifEmpty { sigAlgOID }
  val algorithm =
    checkNotNull(SignatureAlgorithm.fromOid(oid)) { "Unsupported signature algorithm OID $oid" }

  @Suppress("DEPRECATION") // For legacy resources.
  val data = if (signedMessage.hasMessage()) signedMessage.message.value else signedMessage.data

  if (!verifySignature(algorithm, data, signedMessage.signature)) {
    throw SignatureException("Signature is invalid")
  }
}
