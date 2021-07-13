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

package org.wfanet.consentsignaling.client

import org.wfanet.consentsignaling.crypto.hybridencryption.FakeHybridCryptor
import org.wfanet.consentsignaling.crypto.hybridencryption.HybridCryptor
import org.wfanet.consentsignaling.crypto.signage.JavaSecuritySigner
import org.wfanet.consentsignaling.crypto.signage.Signer

/** Signer can verify and sign signatures (currently using java security library implementation) */
var signer: Signer = JavaSecuritySigner()

/**
 * HybridCryptor can encrypt and decrypt data (currently using 'no encryption' implementation, but
 * will soon be changed to TinkCrypto [which is the Crypto implemenation based on Tink]
 */
var hybridCryptor: HybridCryptor = FakeHybridCryptor()
