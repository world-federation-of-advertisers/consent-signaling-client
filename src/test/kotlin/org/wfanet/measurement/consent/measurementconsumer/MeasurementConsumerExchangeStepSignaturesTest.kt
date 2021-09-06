package org.wfanet.measurement.consent.measurementconsumer

import org.wfanet.measurement.consent.client.measurementconsumer.verifyExchangeStepSignatures
import org.wfanet.measurement.consent.testing.AbstractExchangeStepSignaturesFunctionTest
import org.wfanet.measurement.consent.testing.verifyExchangeStepSignaturesFunction

class MeasurementConsumerExchangeStepSignaturesTest : AbstractExchangeStepSignaturesFunctionTest() {
  override val verifyExchangeStepSignatures: verifyExchangeStepSignaturesFunction =
    ::verifyExchangeStepSignatures
}
