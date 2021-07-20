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

import java.nio.file.Paths
import org.wfanet.measurement.common.getRuntimePath

private val TESTDATA_DIR =
  Paths.get(
    "wfa_common_jvm",
    "src",
    "main",
    "kotlin",
    "org",
    "wfanet",
    "measurement",
    "common",
    "crypto",
    "testing",
    "testdata"
  )

const val KEY_ALGORITHM = "EC"

val SERVER_CERT_PEM_FILE = getRuntimePath(TESTDATA_DIR.resolve("server.pem"))!!.toFile()
val SERVER_KEY_FILE = getRuntimePath(TESTDATA_DIR.resolve("server.key"))!!.toFile()

val EDP1_CERT_PEM_FILE = getRuntimePath(TESTDATA_DIR.resolve("edp-1.pem"))!!.toFile()
val EDP1_KEY_FILE = getRuntimePath(TESTDATA_DIR.resolve("edp-1.key"))!!.toFile()
val EDP1_DER_FILE = getRuntimePath(TESTDATA_DIR.resolve("edp-1.der"))!!.toFile()
val EDP1_PRIVATE_KEY_FILE = getRuntimePath(TESTDATA_DIR.resolve("edp-1-private.key"))!!.toFile()
