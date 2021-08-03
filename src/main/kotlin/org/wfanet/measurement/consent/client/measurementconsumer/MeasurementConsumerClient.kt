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

package org.wfanet.measurement.consent.client.measurementconsumer

import com.google.protobuf.ByteString
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.api.v2alpha.SignedData
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.consent.crypto.keystore.PrivateKeyHandle
import org.wfanet.measurement.consent.crypto.signMessage

/** Creates signature of the measurementConsumer's encryptionPublicKey. */
suspend fun createEncryptionPublicKeySignature(
  encryptionPublicKey: EncryptionPublicKey,
  privateKeyHandle: PrivateKeyHandle,
  measurementConsumerX509: ByteString
): SignedData {
  return signMessage<EncryptionPublicKey>(
    message = encryptionPublicKey,
    privateKeyHandle = privateKeyHandle,
    certificate = readCertificate(measurementConsumerX509)
  )
}