package com.ghostprotocol.crypto

import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Relay request signer using ECDSA P-256 with SHA-256 (DER signature). The public key is sent as
 * X.509 SubjectPublicKeyInfo, exactly what `PublicKey.getEncoded()` returns.
 *
 * Why P-256 and not Ed25519: Android Keystore supports P-256 signing from API 23 (minSdk here is
 * 26), including hardware-backed (TEE/StrongBox) non-exportable keys, while java.security Ed25519
 * needs API 33. On Android, pass the Keystore-held key pair; the private key is then never
 * available to app code. [generateSoftware] makes an in-memory key for JVM tests only.
 */
class EcdsaP256Signer(private val privateKey: PrivateKey, publicKey: PublicKey) : RequestSigner {
    override val publicKey: ByteArray = publicKey.encoded

    override fun sign(message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").apply {
            initSign(privateKey)
            update(message)
        }.sign()

    companion object {
        /** In-memory key (NOT hardware-backed). For tests and tools; the app uses Android Keystore. */
        fun generateSoftware(): EcdsaP256Signer {
            val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return EcdsaP256Signer(pair.private, pair.public)
        }
    }
}
