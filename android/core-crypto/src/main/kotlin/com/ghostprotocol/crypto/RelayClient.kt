package com.ghostprotocol.crypto

import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import org.json.JSONArray
import org.json.JSONObject

class RelayException(val status: Int, message: String) : Exception(message)

/**
 * Signs relay requests with the device's relay-auth key, which is separate from the Signal
 * identity key. Scheme: ECDSA P-256 / SHA-256, DER signature; public key as X.509 SPKI DER
 * (see [EcdsaP256Signer]).
 */
interface RequestSigner {
    val publicKey: ByteArray
    fun sign(message: ByteArray): ByteArray
}

/** The relay operations the messaging client needs (lets tests substitute a hostile or broken relay). */
interface RelayApi {
    fun fetchBundle(username: String): FetchedBundle
    fun send(recipientMailbox: String, payload: ByteArray)
    fun inbox(): List<Delivered>
    fun ack(ids: List<String>)
}

class FetchedBundle(val mailboxId: String, val bundle: ByteArray, val oneTimePreKey: ByteArray?)
class Delivered(val id: String, val body: ByteArray)

/**
 * Client for the Ghost_Protocol relay. Everything it sends is already encrypted or public key
 * material. Plain http is refused unless explicitly allowed for loopback testing.
 */
class RelayClient(
    baseUrl: String,
    private val signer: RequestSigner? = null,
    var mailboxId: String? = null,
    allowLoopbackHttpForTests: Boolean = false,
) : RelayApi {
    private val base = baseUrl.trimEnd('/')
    private val random = SecureRandom()
    private val b64 = Base64.getEncoder()
    private val dec = Base64.getDecoder()

    init {
        val ok = base.startsWith("https://") ||
            (allowLoopbackHttpForTests && base.startsWith("http://127.0.0.1"))
        require(ok) { "relay URL must be https" }
    }

    fun register(invite: String, username: String, authPublicKey: ByteArray, bundle: ByteArray, oneTimePreKeys: List<ByteArray>): String {
        val body = JSONObject()
            .put("invite", invite).put("username", username)
            .put("auth_pub", b64.encodeToString(authPublicKey))
            .put("bundle", b64.encodeToString(bundle))
            .put("one_time_prekeys", JSONArray(oneTimePreKeys.map { b64.encodeToString(it) }))
        val resp = JSONObject(String(call("POST", "/v1/register", body.toString().toByteArray(), auth = false)))
        return resp.getString("mailbox_id").also { mailboxId = it }
    }

    override fun fetchBundle(username: String): FetchedBundle {
        val r = JSONObject(String(call("GET", "/v1/bundle/$username", null, auth = false)))
        return FetchedBundle(
            r.getString("mailbox_id"), dec.decode(r.getString("bundle")),
            if (r.has("one_time_prekey")) dec.decode(r.getString("one_time_prekey")) else null,
        )
    }

    override fun send(recipientMailbox: String, payload: ByteArray) {
        call("POST", "/v1/send/$recipientMailbox", payload, auth = true)
    }

    override fun inbox(): List<Delivered> {
        val arr = JSONObject(String(call("GET", "/v1/inbox", null, auth = true))).getJSONArray("messages")
        return (0 until arr.length()).map {
            val m = arr.getJSONObject(it)
            Delivered(m.getString("id"), dec.decode(m.getString("body")))
        }
    }

    override fun ack(ids: List<String>) {
        call("POST", "/v1/ack", JSONObject().put("ids", JSONArray(ids)).toString().toByteArray(), auth = true)
    }

    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun call(method: String, path: String, body: ByteArray?, auth: Boolean): ByteArray {
        val conn = URL(base + path).openConnection() as HttpURLConnection
        conn.requestMethod = method
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        conn.instanceFollowRedirects = false
        val payload = body ?: ByteArray(0)
        if (auth) {
            val s = signer ?: throw RelayException(0, "no signer configured")
            val mb = mailboxId ?: throw RelayException(0, "no mailbox configured")
            val ts = (System.currentTimeMillis() / 1000).toString()
            val nonce = ByteArray(12).also { random.nextBytes(it) }.let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
            val digest = hex(MessageDigest.getInstance("SHA-256").digest(payload))
            val canonical = "$method\n$path\n$ts\n$nonce\n$digest".toByteArray()
            conn.setRequestProperty("X-Mailbox", mb)
            conn.setRequestProperty("X-Timestamp", ts)
            conn.setRequestProperty("X-Nonce", nonce)
            conn.setRequestProperty("X-Signature", b64.encodeToString(s.sign(canonical)))
        }
        if (body != null) {
            conn.doOutput = true
            conn.setFixedLengthStreamingMode(payload.size)
            conn.setRequestProperty("Content-Type", "application/octet-stream")
            conn.outputStream.use { it.write(payload) }
        }
        val code = conn.responseCode
        val data = (if (code in 200..299) conn.inputStream else conn.errorStream)?.use { it.readBytes() } ?: ByteArray(0)
        conn.disconnect()
        if (code !in 200..299) throw RelayException(code, "relay returned $code")
        return data
    }
}
