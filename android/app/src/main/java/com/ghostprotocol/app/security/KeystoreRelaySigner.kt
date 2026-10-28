package com.ghostprotocol.app.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.ghostprotocol.crypto.EcdsaP256Signer
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec

/**
 * Relay-authentication key held in Android Keystore (ECDSA P-256). The private key is generated
 * inside the keystore and is non-exportable: app code can ask it to sign, never to reveal it.
 * StrongBox is requested when the device has it, otherwise the TEE / software keystore is used;
 * [isInsideSecureHardware] reports which one actually happened.
 *
 * This key only authenticates requests to the relay. It is separate from the Signal identity key.
 */
object KeystoreRelaySigner {
    const val ALIAS = "ghost_relay_auth_p256"

    fun exists(alias: String = ALIAS): Boolean = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias)

    fun getOrCreate(alias: String = ALIAS): EcdsaP256Signer {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(alias)) generate(alias)
        val priv = ks.getKey(alias, null) as PrivateKey
        val pub = ks.getCertificate(alias).publicKey
        return EcdsaP256Signer(priv, pub)
    }

    private fun generate(alias: String) {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply { if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true) }
            .build()
        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        try {
            gen.initialize(spec(true)); gen.generateKeyPair()
        } catch (e: Exception) { // StrongBox absent on this device: fall back to the normal keystore
            val g2 = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            g2.initialize(spec(false)); g2.generateKeyPair()
        }
    }

    fun delete(alias: String = ALIAS) {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.apply { if (containsAlias(alias)) deleteEntry(alias) }
    }
}
