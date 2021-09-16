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

package org.wfanet.measurement.consent.crypto

import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetReader
import com.google.crypto.tink.PemKeyType
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.proto.EcPointFormat
import com.google.crypto.tink.proto.EciesAeadDemParams
import com.google.crypto.tink.proto.EciesAeadHkdfParams
import com.google.crypto.tink.proto.EciesAeadHkdfPrivateKey
import com.google.crypto.tink.proto.EciesAeadHkdfPublicKey
import com.google.crypto.tink.proto.EciesHkdfKemParams
import com.google.crypto.tink.proto.EllipticCurveType
import com.google.crypto.tink.proto.EncryptedKeyset
import com.google.crypto.tink.proto.HashType
import com.google.crypto.tink.proto.KeyData
import com.google.crypto.tink.proto.KeyStatusType
import com.google.crypto.tink.proto.KeyTemplate
import com.google.crypto.tink.proto.Keyset
import com.google.crypto.tink.proto.OutputPrefixType
import com.google.crypto.tink.subtle.EllipticCurves
import com.google.crypto.tink.subtle.EngineFactory
import com.google.crypto.tink.subtle.Enums
import com.google.crypto.tink.subtle.Random
import com.google.protobuf.ByteString
import java.io.IOException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.Key
import java.security.KeyFactory
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

enum class KeyParty {
  PUBLIC,
  PRIVATE
}

class TinkDerKeysetReader
constructor(
  private val keyParty: KeyParty,
  private val derKey: ByteString,
  private val pemKeyType: PemKeyType
) : KeysetReader {
  @Throws(IOException::class)
  override fun read(): Keyset? {
    val keySet = Keyset.newBuilder()
    val javaKey =
      when (keyParty) {
        KeyParty.PRIVATE -> getPrivateKey(derKey.toByteArray())
        KeyParty.PUBLIC -> getPublicKey(derKey.toByteArray())
      }
    val keyData: KeyData =
      when (javaKey) {
        is ECPublicKey -> convertEcPublicKey(javaKey, pemKeyType)
        is ECPrivateKey -> convertEcPrivateKey(javaKey, pemKeyType)
        else -> return null
      }
    val key =
      Keyset.Key.newBuilder()
        .setKeyData(keyData)
        .setStatus(KeyStatusType.ENABLED)
        .setOutputPrefixType(OutputPrefixType.RAW)
        .setKeyId(Random.randInt())
        .build()
    keySet.addKey(key)
    keySet.primaryKeyId = keySet.getKey(0).keyId
    return keySet.build()
  }

  @Throws(IOException::class)
  override fun readEncrypted(): EncryptedKeyset {
    throw UnsupportedOperationException()
  }

  private fun validate(key: Key): Key {
    val ecKey = key as ECKey
    val ecParams = ecKey.params
    if (!EllipticCurves.isNistEcParameterSpec(ecParams)) {
      throw GeneralSecurityException("unsupport EC spec: $ecParams")
    }
    val foundKeySizeInBits = EllipticCurves.fieldSizeInBits(ecParams.curve)
    if (foundKeySizeInBits != pemKeyType.keySizeInBits) {
      throw GeneralSecurityException(
        String.format(
          "invalid EC key size, want %d got %d",
          pemKeyType.keySizeInBits,
          foundKeySizeInBits
        )
      )
    }
    return key
  }

  private fun getPublicKey(key: ByteArray): Key {
    val keyFactory = EngineFactory.KEY_FACTORY.getInstance(pemKeyType.keyType) as KeyFactory
    return validate(keyFactory.generatePublic(X509EncodedKeySpec(key)))
  }

  private fun getPrivateKey(key: ByteArray): Key {
    val keyFactory = EngineFactory.KEY_FACTORY.getInstance(pemKeyType.keyType) as KeyFactory
    return validate(keyFactory.generatePrivate(PKCS8EncodedKeySpec(key)))
  }

  private fun getHashType(pemKeyType: PemKeyType): HashType {
    when (pemKeyType.hash) {
      Enums.HashType.SHA256 -> return HashType.SHA256
      Enums.HashType.SHA384 -> return HashType.SHA384
      Enums.HashType.SHA512 -> return HashType.SHA512
      else -> {}
    }
    throw IllegalArgumentException("unsupported hash type: " + pemKeyType.hash.name)
  }

  private fun getCurveType(pemKeyType: PemKeyType?): EllipticCurveType {
    when (pemKeyType!!.keySizeInBits) {
      256 -> return EllipticCurveType.NIST_P256
      384 -> return EllipticCurveType.NIST_P384
      521 -> return EllipticCurveType.NIST_P521
      else -> {}
    }
    throw IllegalArgumentException("unsupported curve for key size: " + pemKeyType.keySizeInBits)
  }

  private fun toUnsignedIntByteString(i: BigInteger): ByteString {
    val twosComplement = i.toByteArray()
    return if (twosComplement[0] == 0.toByte()) {
      ByteString.copyFrom(twosComplement, 1, twosComplement.size - 1)
    } else ByteString.copyFrom(twosComplement)
  }

  private fun generateEciesAeadHkdfParams(pemKeyType: PemKeyType): EciesAeadHkdfParams {
    require(pemKeyType.algorithm == "ECDSA") { "Only EC is currently supported" }
    val eciesHkdfKemParams =
      EciesHkdfKemParams.newBuilder()
        .apply {
          hkdfHashType = getHashType(pemKeyType)
          curveType = getCurveType(pemKeyType)
          // hkdfSalt = KEJ - Should we be setting a Salt??
        }
        .build()
    val aes128GCM = KeyTemplates.get("AES128_GCM")
    val eciesAeadDemParams =
      EciesAeadDemParams.newBuilder()
        .apply {
          aeadDem =
            KeyTemplate.newBuilder()
              .apply {
                typeUrl = aes128GCM.typeUrl
                value = ByteString.copyFrom(aes128GCM.value)
                outputPrefixType =
                  when (aes128GCM.outputPrefixType) {
                    com.google.crypto.tink.KeyTemplate.OutputPrefixType.TINK ->
                      OutputPrefixType.TINK
                    com.google.crypto.tink.KeyTemplate.OutputPrefixType.LEGACY ->
                      OutputPrefixType.LEGACY
                    com.google.crypto.tink.KeyTemplate.OutputPrefixType.RAW -> OutputPrefixType.RAW
                    com.google.crypto.tink.KeyTemplate.OutputPrefixType.CRUNCHY ->
                      OutputPrefixType.CRUNCHY
                    else -> OutputPrefixType.UNKNOWN_PREFIX
                  }
              }
              .build()
        }
        .build()
    return EciesAeadHkdfParams.newBuilder()
      .apply {
        kemParams = eciesHkdfKemParams
        demParams = eciesAeadDemParams
        ecPointFormat = EcPointFormat.UNCOMPRESSED
      }
      .build()
  }

  private fun convertEcPublicKey(key: ECPublicKey, pemKeyType: PemKeyType): KeyData {
    val eciesAeadHkdfPublicKey =
      EciesAeadHkdfPublicKey.newBuilder()
        .apply {
          version = 0 // KEJ - TinkEcdsaPublicKeyTypeManager().version - Where can I get this??
          params = generateEciesAeadHkdfParams(pemKeyType)
          x = toUnsignedIntByteString(key.w.affineX)
          y = toUnsignedIntByteString(key.w.affineY)
        }
        .build()
    return KeyData.newBuilder()
      .apply {
        typeUrl = HybridConfig.ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL
        value = eciesAeadHkdfPublicKey.toByteString()
        keyMaterialType = KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC
      }
      .build()
  }

  private fun convertEcPrivateKey(key: ECPrivateKey, pemKeyType: PemKeyType): KeyData {
    val eciesAeadHkdfPublicKey =
      EciesAeadHkdfPublicKey.newBuilder()
        .apply {
          version = 0 // KEJ - TinkEcdsaPublicKeyTypeManager().version - Where can I get this??
          params = generateEciesAeadHkdfParams(pemKeyType)
          x = toUnsignedIntByteString(key.params.generator.affineX)
          y = toUnsignedIntByteString(key.params.generator.affineY)
        }
        .build()
    val eciesAeadHkdfPrivateKey =
      EciesAeadHkdfPrivateKey.newBuilder()
        .apply {
          version = 0 // KEJ - TinkEcdsaPrivateKeyTypeManager().version - Where can I get this??
          publicKey = eciesAeadHkdfPublicKey
          keyValue = toUnsignedIntByteString(key.s)
        }
        .build()
    return KeyData.newBuilder()
      .apply {
        typeUrl = HybridConfig.ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL
        value = eciesAeadHkdfPrivateKey.toByteString()
        keyMaterialType = KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC
      }
      .build()
  }
}
