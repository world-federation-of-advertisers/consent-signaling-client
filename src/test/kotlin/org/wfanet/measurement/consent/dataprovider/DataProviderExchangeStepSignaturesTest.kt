package org.wfanet.measurement.consent.dataprovider

import org.wfanet.measurement.consent.client.dataprovider.verifyExchangeStepSignatures
import org.wfanet.measurement.consent.testing.AbstractExchangeStepSignaturesFunctionTest
import org.wfanet.measurement.consent.testing.verifyExchangeStepSignaturesFunction

class DataProviderExchangeStepSignaturesTest : AbstractExchangeStepSignaturesFunctionTest() {
  override val verifyExchangeStepSignatures: verifyExchangeStepSignaturesFunction =
    ::verifyExchangeStepSignatures
}
