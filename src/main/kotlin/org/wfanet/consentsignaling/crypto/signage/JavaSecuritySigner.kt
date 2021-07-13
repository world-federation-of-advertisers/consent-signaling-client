package org.wfanet.consentsignaling.crypto.signage

import com.google.protobuf.ByteString
import java.io.ByteArrayInputStream
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import org.wfanet.consentsignaling.crypto.keys.PrivateKeyHandle
import org.wfanet.measurement.api.v2alpha.Certificate

/**
 * A Signer implementation using Java Security classes that can perform data signing and
 * verification of signatures
 */
class JavaSecuritySigner : Signer {

  override fun sign(
    certificate: Certificate,
    privateKeyHandle: PrivateKeyHandle,
    data: ByteString
  ): ByteArray {
    val x509Certificate = decodeCertificate(certificate)
    val javaPrivateKey = privateKeyHandle.toJavaPrivateKey()
    val signature = Signature.getInstance(x509Certificate.sigAlgName)
    signature.setParameter(
      PSSParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA256,
        generatePrivateSaltLength(javaPrivateKey),
        1
      )
    )
    signature.initSign(javaPrivateKey)
    signature.update(data.toByteArray())
    return signature.sign()
  }

  override fun verify(certificate: Certificate, signature: ByteArray, data: ByteString): Boolean {
    val x509Certificate = decodeCertificate(certificate)
    val javaPublicKey = x509Certificate.publicKey
    val javaSignature = Signature.getInstance(x509Certificate.sigAlgName)
    javaSignature.initVerify(javaPublicKey)
    javaSignature.setParameter(
      PSSParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec.SHA256,
        generatePublicSaltLength(javaPublicKey),
        1
      )
    )
    javaSignature.update(data.toByteArray())
    return javaSignature.verify(signature)
  }

  /** Decodes an X.509 certificate byte array into a Java Security Certificate object */
  private fun decodeCertificate(certificate: Certificate): X509Certificate {
    val javaCertificate =
      CertificateFactory.getInstance(SignerConstants.CERTIFICATE_TYPE)
        .generateCertificate(ByteArrayInputStream(certificate.x509Der.toByteArray()))
    if (javaCertificate is X509Certificate) {
      return javaCertificate
    } else {
      throw Signer.CertificateTypeNotSupported(SignerConstants.CERTIFICATE_TYPE)
    }
  }

  private fun generatePrivateSaltLength(privateKey: java.security.PrivateKey): Int {
    val keySize = (privateKey as RSAPrivateKey).modulus.bitLength()
    return generateSaltLength(keySize)
  }

  private fun generatePublicSaltLength(publicKey: java.security.PublicKey): Int {
    val keySize = (publicKey as RSAPublicKey).modulus.bitLength()
    return generateSaltLength(keySize)
  }

  /** Calculates a salt length used for the PSSParameterSpec */
  private fun generateSaltLength(keySize: Int): Int {
    return ((keySize + 6) / 8) - 32 - 2
  }
}
