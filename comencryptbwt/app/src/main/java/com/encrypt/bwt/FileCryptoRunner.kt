// FileCryptoRunner.kt
package com.encrypt.bwt

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import com.encrypt.bwt.aegis.VerificationFailedException
import org.bouncycastle.crypto.InvalidCipherTextException
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.IOException
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException

/**
 * Cifra/descifra un archivo POR FLUJO (sin cargarlo entero en memoria) en un hilo
 * de fondo. Funciona con archivos de cualquier tamaño (cientos de MB, GB).
 *
 * El formato es el mismo que el de las versiones anteriores de la app.
 * Si la operación falla o se cancela, el archivo de salida parcial se borra.
 */
object FileCryptoRunner {

    class Job {
        @Volatile
        var cancelled = false
            private set

        fun cancel() {
            cancelled = true
        }
    }

    sealed class Result {
        data class Success(val bytesProcessed: Long) : Result()
        object Cancelled : Result()
        data class Failure(val message: String) : Result()
    }

    private const val BUFFER = 64 * 1024

    /**
     * @param onProgress (bytes procesados, tamaño total o -1 si se desconoce). Se llama en el hilo principal.
     * @param onResult   se llama una sola vez en el hilo principal.
     */
    fun start(
        context: Context,
        encrypt: Boolean,
        cipher: String,
        password: String,
        inUri: Uri,
        outUri: Uri,
        totalBytes: Long,
        onProgress: (done: Long, total: Long) -> Unit,
        onResult: (Result) -> Unit
    ): Job {
        val app = context.applicationContext
        val job = Job()
        val main = Handler(Looper.getMainLooper())

        val listener = object : StreamCrypto.Listener {
            private var lastPost = 0L
            override fun onProgress(bytesRead: Long) {
                val now = SystemClock.uptimeMillis()
                if (now - lastPost >= 200) {
                    lastPost = now
                    main.post { onProgress.invoke(bytesRead, totalBytes) }
                }
            }

            override fun isCancelled(): Boolean = job.cancelled
        }

        Thread({
            val result: Result = try {
                val input = app.contentResolver.openInputStream(inUri)
                    ?: throw IOException("Cannot open the input file")
                val output = app.contentResolver.openOutputStream(outUri, "wt")
                    ?: run {
                        input.close()
                        throw IOException("Cannot open the output file")
                    }

                BufferedInputStream(input, BUFFER).use { i ->
                    BufferedOutputStream(output, BUFFER).use { o ->
                        if (encrypt) {
                            StreamCrypto.encrypt(cipher, password, i, o, listener)
                        } else {
                            StreamCrypto.decrypt(cipher, password, i, o, listener)
                        }
                    }
                }
                Result.Success(if (totalBytes >= 0) totalBytes else 0L)
            } catch (t: Throwable) {
                t.printStackTrace()
                // Nunca dejamos un archivo parcial (ni texto en claro sin autenticar) en el destino.
                FileHelper.deleteQuietly(app, outUri)
                if (t is StreamCrypto.CancelledException || job.cancelled) {
                    Result.Cancelled
                } else {
                    Result.Failure(describe(t))
                }
            }
            main.post { onResult(result) }
        }, "file-crypto").start()

        return job
    }

    private fun describe(t: Throwable): String = when (t) {
        is InvalidCipherTextException,
        is VerificationFailedException,
        is AEADBadTagException,
        is BadPaddingException ->
            "Decryption failed: wrong key, wrong cipher, or the file is corrupted."
        is IllegalArgumentException -> t.message ?: "Invalid data"
        is OutOfMemoryError -> "Not enough memory to process this file."
        is IOException -> "I/O error: ${t.message ?: "unknown"} (is there enough free space?)"
        else -> t.message ?: t.javaClass.simpleName
    }
}
