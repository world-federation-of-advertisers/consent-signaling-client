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

package org.wfanet.measurement.consent.crypto

import com.google.protobuf.ByteString
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.X509Certificate
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.jceProvider

/**
 * Signs [data] using this [PrivateKey].
 *
 * @param certificate the [X509Certificate] that can be used to verify the signature
 */
fun PrivateKey.sign(certificate: X509Certificate, data: ByteString): ByteString {
  val signer = Signature.getInstance(certificate.sigAlgName, jceProvider)
  signer.initSign(this)
  signer.update(data.asReadOnlyByteBuffer())
  return ByteString.copyFrom(signer.sign())
}

/**
 * Verifies that the [signature] for [data] was signed by the entity represented by this
 * [X509Certificate].
 */
fun X509Certificate.verifySignature(data: ByteString, signature: ByteString): Boolean {
  val verifier = Signature.getInstance(this.sigAlgName, jceProvider)
  verifier.initVerify(this)
  verifier.update(data.asReadOnlyByteBuffer())
  return verifier.verify(signature.toByteArray())
}

/**
 * Verifies that the [signedData] was signed by the entity represented by this [X509Certificate].
 */
fun X509Certificate.verifySignature(signedData: SignedData): Boolean {
  val verifier = Signature.getInstance(this.sigAlgName, jceProvider)
  verifier.initVerify(this)
  verifier.update(signedData.data.asReadOnlyByteBuffer())
  return verifier.verify(signedData.signature.toByteArray())
}
