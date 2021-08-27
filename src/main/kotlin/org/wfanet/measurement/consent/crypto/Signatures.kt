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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.runBlocking
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.jceProvider
import org.wfanet.measurement.consent.crypto.exception.InvalidSignatureException

/**
 * Signs [data] using this [PrivateKey].
 *
 * @param certificate the [X509Certificate] that can be used to verify the signature
 */
fun PrivateKey.sign(certificate: X509Certificate, data: ByteString): ByteString {
  val deferredSig = this.signFlow(certificate, flow { emit(data) })
  val signature: ByteString
  runBlocking {
    deferredSig.first.collect()
    signature = deferredSig.second.await()
  }
  return signature
}

/**
 * Signs [data] using this [PrivateKey]. Takes in a [Flow<ByteString>] for signing streaming data.
 *
 * Note that the deferred output (the signature) will only be ready when the Flow has been fully
 * collected.
 *
 * @param certificate the [X509Certificate] that can be used to verify the signature
 */
fun PrivateKey.signFlow(
  certificate: X509Certificate,
  data: Flow<ByteString>
): Pair<Flow<ByteString>, Deferred<ByteString>> {
  val signer = Signature.getInstance(certificate.sigAlgName, jceProvider)
  val deferredSig = CompletableDeferred<ByteString>()
  signer.initSign(this)
  val outFlow =
    data.onEach { signer.update(it.asReadOnlyByteBuffer()) }.onCompletion {
      deferredSig.complete(ByteString.copyFrom(signer.sign()))
    }
  return outFlow to deferredSig
}

/**
 * Verifies that the [signature] for [data] was signed by the entity represented by this
 * [X509Certificate].
 */
fun X509Certificate.verifySignature(data: ByteString, signature: ByteString): Boolean {
  val resultFlow = this.verifySignedFlow(flow { emit(data) }, signature, "File")
  return try {
    runBlocking { resultFlow.collect() }
    true
  } catch (e: InvalidSignatureException) {
    false
  }
}

/**
 * Verifies that the [signedData] was signed by the entity represented by this [X509Certificate].
 */
fun X509Certificate.verifySignature(signedData: SignedData): Boolean {
  return verifySignature(signedData.data, signedData.signature)
}

/**
 * Verifies that the [signature] for the Flow [data] was signed by the entity represented by this
 * [X509Certificate].
 *
 * The output is the downstream Flow of [data]. If [data] is found to not match [signature] upon
 * collecting the flow, this will throw an [IllegalArgumentException].
 */
@Throws(InvalidSignatureException::class)
fun X509Certificate.verifySignedFlow(
  data: Flow<ByteString>,
  signature: ByteString,
  blobKey: String
): Flow<ByteString> {
  val verifier = Signature.getInstance(this.sigAlgName, jceProvider)

  verifier.initVerify(this)
  return data.onEach { verifier.update(it.asReadOnlyByteBuffer()) }.onCompletion {
    if (!verifier.verify(signature.toByteArray())) {
      throw InvalidSignatureException(blobKey)
    }
  }
}
