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
