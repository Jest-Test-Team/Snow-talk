package app.snowtalk.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The anonymous-token wallet: the only chat-related state the app keeps.
 * AES-256-GCM under an Android Keystore key (StrongBox when the device has one),
 * stored as `iv ‖ ciphertext` in app-private storage.
 */
class WalletStore(context: Context) {
    private val file = File(context.filesDir, "wallet.bin")

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        fun generate(strongBox: Boolean): SecretKey {
            val spec = KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(strongBox)
                .build()
            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            gen.init(spec)
            return gen.generateKey()
        }
        return try {
            generate(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    fun save(bytes: ByteArray) {
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, key())
        val tmp = File(file.path + ".tmp")
        tmp.writeBytes(c.iv + c.doFinal(bytes))
        tmp.renameTo(file)
    }

    fun load(): ByteArray? = runCatching {
        val b = file.readBytes()
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, IV_LEN))
        c.doFinal(b, IV_LEN, b.size - IV_LEN)
    }.getOrNull()

    private companion object {
        const val ALIAS = "snowtalk-wallet"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val IV_LEN = 12
    }
}
