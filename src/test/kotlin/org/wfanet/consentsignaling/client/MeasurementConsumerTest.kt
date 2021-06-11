package org.wfanet.consentsignaling.client

import org.wfanet.consentsignaling.client.MeasurementConsumer
import org.junit.Test

class MeasurementConsumerTest {

  val localDataProviderList = listOf("dataProviderProto1", "dataProviderProto2", "dataProviderProto3") // assume the type is DataProvider

  @Test
  fun `measurement consumer create measurement spec`() {
    val measurementPublicKey = "measurementPublicKey"

    val measurementSpecProto = MeasurementConsumer.createMeasurementSpec(
      measurementPublicKey // Measurement's Consumers Public Key
    )
    // assert here that the measurement spec proto was created correctly
  }

  @Test
  fun `measurement consumer create measurement`() {
    val mcCertificate = "measurementConsumerCertificate"
    val mcPrivateKey = "measurementConsumerPrivateKey"

    val measurementName = "myMeasurement"

    // Create the required Measurement Spec
    val measurementPublicKey = "measurementPublicKey" // Where does this come from?
    val measurementSpecProto = MeasurementConsumer.createMeasurementSpec(measurementPublicKey)

    // Create the data provider list
    val myDataProviderList = localDataProviderList.filter { true /** some filter **/ }
    val dataProviderListSalt = MeasurementConsumer.createDataProviderListSalt()

    // Create the required Requisition Spec (un-encrypted here)
    val eventGroups = NotSureWhereThisUtilityLives.createEventGroup(/** ... **/)
    val requisitionSpecProto = MeasurementConsumer.createRequisitionSpec(
      eventGroups, // Event Group Entry List
      measurementPublicKey, // Measurement Public Key
      myDataProviderList, // List of Data Providers
      dataProviderListSalt, // Measurement Salt for DataProvider Hash
    )
    /**
     * Note: createRequisitionSpec will
     *   1. Create the salted hash of data providers and store in the RequisitionSpec
     */

    // Create the Data Provider Entry List
    val dataProviderEntriesProto = MeasurementConsumer.createDataProviderEntryList(
      myDataProviderList, // List of Data Providers
      requisitionSpecProto, // Requisition Spec (to be encrypted)
      mcPrivateKey // Measurement Consumer Private Key for Signing the RequisitionSpec
    )
    /**
     * Note: createDataProviderEntryList will
     *   1. Sign the Requisition Spec with the MC Private Key
     *   2. Encrypt the Requisition Spec with the Measurement Public Key (stored in the Requisition Spec)
     */

    // Create the required Protocol Config
    val protocolConfigProto = MeasurementConsumer.createProtocolConfig(MeasurementConsumer.DEFAULT_REACH_AND_FREQUENCY)

    val measurementProto = MeasurementConsumer.createMeasurement(
      measurementName, // Measurement Name
      mcCertificate, // Measurement Consumer Certificate
      measurementSpecProto, // Measurement Spec
      myDataProviderList, // Data Provider List
      dataProviderListSalt, // Data Provider List Salt
      dataProviderEntriesProto, // Data Provider Entries (each containing a Requisition Spec)
      protocolConfigProto
    )
    /**
     * Note: createMeasurement will
     *   1. Create a serialized list of data providers
     */
    /**
     * Assert here that the measurement was created correctly
     */
  }

}
