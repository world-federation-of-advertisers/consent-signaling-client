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

val EDP_1_CERT_PEM_FILE = TESTDATA_DIR_PATH.resolve("edp_1.pem").toFile()
val EDP_1_KEY_FILE = TESTDATA_DIR_PATH.resolve("edp_1.key").toFile()

val MC_1_CERT_PEM_FILE = TESTDATA_DIR_PATH.resolve("mc_1.pem").toFile()
val MC_1_KEY_FILE = TESTDATA_DIR_PATH.resolve("mc_1.key").toFile()

val DUCHY_1_NON_AGG_CERT_PEM_FILE = TESTDATA_DIR_PATH.resolve("non_aggregator_1.pem").toFile()
val DUCHY_1_NON_AGG_KEY_FILE = TESTDATA_DIR_PATH.resolve("non_aggregator_1.key").toFile()

val DUCHY_AGG_CERT_PEM_FILE = TESTDATA_DIR_PATH.resolve("aggregator.pem").toFile()
val DUCHY_AGG_KEY_FILE = TESTDATA_DIR_PATH.resolve("aggregator.key").toFile()

val KEY_ALGORITHM = "EC"
