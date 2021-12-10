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

package org.wfanet.measurement.consent.testing

import java.io.File
import java.nio.file.Paths
import org.wfanet.measurement.common.crypto.SigningKeyHandle
import org.wfanet.measurement.common.crypto.readCertificate
import org.wfanet.measurement.common.crypto.readPrivateKey

private val TESTDATA_DIR_PATH =
  Paths.get(
    "src",
    "main",
    "kotlin",
    "org",
    "wfanet",
    "measurement",
    "consent",
    "testing",
  )

private fun loadTestFile(filename: String): File =
  requireNotNull(TESTDATA_DIR_PATH.resolve(filename).toFile()) {
    "Test resource file not found: $filename"
  }

fun readSigningKeyHandle(certificatePem: File, privateKeyPem: File): SigningKeyHandle {
  val certificate = readCertificate(certificatePem)
  return SigningKeyHandle(
    certificate,
    readPrivateKey(privateKeyPem, certificate.publicKey.algorithm)
  )
}

val EDP_1_CERT_PEM_FILE = loadTestFile("edp_1.pem")
val EDP_1_KEY_FILE = loadTestFile("edp_1.key")

val MC_1_CERT_PEM_FILE = loadTestFile("mc_1.pem")
val MC_1_KEY_FILE = loadTestFile("mc_1.key")

val DUCHY_1_NON_AGG_CERT_PEM_FILE = loadTestFile("non_aggregator_1.pem")
val DUCHY_1_NON_AGG_KEY_FILE = loadTestFile("non_aggregator_1.key")

val DUCHY_AGG_CERT_PEM_FILE = loadTestFile("aggregator.pem")
val DUCHY_AGG_KEY_FILE = loadTestFile("aggregator.key")
