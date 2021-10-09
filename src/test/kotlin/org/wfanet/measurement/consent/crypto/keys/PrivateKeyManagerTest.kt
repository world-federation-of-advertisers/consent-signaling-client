package org.wfanet.measurement.consent.crypto.keys

import com.google.common.truth.Truth.assertThat
import com.google.protobuf.ByteString
import kotlinx.coroutines.runBlocking
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.wfanet.measurement.api.v2alpha.EncryptionPublicKey
import org.wfanet.measurement.common.crypto.Aead
import org.wfanet.measurement.storage.testing.InMemoryStorageClient

@RunWith(JUnit4::class)
class PrivateKeyManagerTest {
  private val fakeAead = object : Aead{
    override fun encrypt(plaintext: ByteString): ByteString {
      return ByteString.copyFrom(plaintext.reversed().toByteArray())
    }

    override fun decrypt(ciphertext: ByteString): ByteString {
      return ByteString.copyFrom(ciphertext.reversed().toByteArray())
    }
  }

  @Test
  fun `To parties encrypt and decrypt data`() = runBlocking {
    // Alice Setup + Key Generation
    val alicePrivateKeyManager = TinkPrivateKeyManager(fakeAead, InMemoryStorageClient())
    val alicePrivateKeyHandle = alicePrivateKeyManager.generatePrivateKey("alicePrivateKey")
    // Alice sends their public key to Bob
    val aliceEncryptionPublicKey: EncryptionPublicKey = alicePrivateKeyHandle.getPublicKeyHandle().getEncryptionPublicKey()

    // Bob Setup + Key Generation
    val bobStorageClient = TinkPrivateKeyManager(fakeAead, InMemoryStorageClient())
    val bobPrivateKeyHandle = bobStorageClient.generatePrivateKey("bobPrivateKey")
    // Bob sends their public key to Alice
    val bobEncryptionPublicKey: EncryptionPublicKey = bobPrivateKeyHandle.getPublicKeyHandle().getEncryptionPublicKey()

    // Alice converts EncryptionPublicKey proto to PublicKeyHandle
    val bobPublicKeyHandle = PublicKeyHandle.fromEncryptionPublicKey(bobEncryptionPublicKey)
    // Alice send an encrypted message to Bob
    val aliceSecretMessage = ByteString.copyFrom("hello bob".toByteArray())
    val aliceCipherText = bobPublicKeyHandle.encrypt(aliceSecretMessage)

    // Bob Receives Alice's Message
    assertThat(aliceCipherText).isNotEqualTo(aliceSecretMessage)
    // Bob decodes their message
    val alicePlainText = bobPrivateKeyHandle.decrypt(aliceCipherText)
    assertThat(alicePlainText).isEqualTo(aliceSecretMessage)

    // Bob replies
    // Bob converts EncryptionPublicKey proto to PublicKeyHandle
    val alicePublicKeyHandle = PublicKeyHandle.fromEncryptionPublicKey(aliceEncryptionPublicKey)
    // Bob send an encrypted message to Alice
    val bobSecretMessage = ByteString.copyFrom("thanks alice".toByteArray())
    val bobCipherText = alicePublicKeyHandle.encrypt(aliceSecretMessage)

    // Alice Receives Bob's Message
    assertThat(bobCipherText).isNotEqualTo(bobSecretMessage)
    // Alice decodes their message
    val bobPlainText = alicePrivateKeyHandle.decrypt(bobCipherText)
    assertThat(bobPlainText).isEqualTo(bobSecretMessage)
  }
}
