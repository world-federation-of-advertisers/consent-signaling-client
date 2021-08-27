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

// TODO: Move this file to common-jvm
package org.wfanet.measurement.consent.crypto.exception

/**
 * Indicates that there is a problem matching data to a signature. Either the signature is invalid
 * for the data or can't be found at all.
 */
class InvalidSignatureException : Exception {
  val code: Code

  constructor(code: Code) : super() {
    this.code = code
  }

  constructor(code: Code, buildMessage: () -> String) : super(buildMessage()) {
    this.code = code
  }

  enum class Code {
    /** Signature blob path could not be found. */
    SIGNATURE_BLOB_NOT_FOUND,

    /** Signature blob does not match provided data. */
    SIGNATURE_INVALID,
  }
}
