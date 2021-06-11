package org.wfanet.consentsignaling.client

import org.wfanet.consentsignaling.client.Kingdom
import org.junit.Test
import org.wfanet.measurement.api.v2alpha.Measurement

class KingdomTest {

  @Test
  fun `kingdom create requisition`() {
    val measurementProto = Measurement()

    val duchies = listOf<DutchyEntries> () // Not sure where this list comes from?

    val requisition = Kingdom.createRequisition(
      measurement, /** Measurement Proto Message Containing
        Measurement Name
        Measurement Consumer Certificate
        Measurement Spec (Signed)
        Protocol Config
        Data Provider Entries.. **/
      duchies
    )
    /**
     * Assert here that the requisition was created correctly
     */
  }
}

