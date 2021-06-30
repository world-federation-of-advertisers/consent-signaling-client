package org.wfanet.consentsignaling.client

import org.wfanet.consentsignaling.crypto.Crypto
import org.wfanet.consentsignaling.crypto.NoCrypto
import org.wfanet.consentsignaling.crypto.signage.JavaSecuritySignage
import org.wfanet.consentsignaling.crypto.signage.Signage

/**
 * signage can verify and sign signatures (currently using java security library implementation)
 */
var signage: Signage = JavaSecuritySignage()

/**
 * crypto can encrypt and decrypt data (currently using 'no encryption' implementation, but will
 * soon be changed to TinkCrypto [which is the Crypto implemenation based on Tink]
 */
var crypto: Crypto = NoCrypto()
