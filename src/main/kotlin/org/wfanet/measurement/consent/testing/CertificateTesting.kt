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

private const val TESTDATA_DIR = "src/main/kotlin/org/wfanet/measurement/consent/testing/"

val EDP_1_CERT_PEM_FILE = File("${TESTDATA_DIR}edp_1_server.pem")
val EDP_1_KEY_FILE = File("${TESTDATA_DIR}edp_1_server.key")

val DUCHY_1_NON_AGG_CERT_PEM_FILE = File("${TESTDATA_DIR}non_aggregator_1_server.pem")
val DUCHY_1_NON_AGG_KEY_FILE = File("${TESTDATA_DIR}non_aggregator_1_server.key")

val DUCHY_AGG_CERT_PEM_FILE = File("${TESTDATA_DIR}aggregator_server.pem")
val DUCHY_AGG_KEY_FILE = File("${TESTDATA_DIR}aggregator_server.key")
