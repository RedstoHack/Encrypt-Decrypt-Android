//encryptshareactivity
package com.encrypt.bwt

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class EncryptShareActivity : AppCompatActivity() {

    private var selectedCipher = "AES"
    private var isFile = false
    private var fileUri: Uri? = null
    private var inputText: String? = null

    // Estado de la operación de archivo (se guarda mientras se muestra "Guardar como")
    private var pendingKey: String? = null
    private var pendingCipher: String = "AES"
    private var job: FileCryptoRunner.Job? = null
    private var progressDialog: AlertDialog? = null

    private val saveAsLauncher = registerForActivityResult(CreateAnyDocument()) { outUri: Uri? ->
        onSaveTargetChosen(outUri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val clipText = intent?.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
        val clipUri = intent?.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)

        if (clipText.isNullOrEmpty() && clipUri == null) {
            showFinalDialog("No text or file to encrypt.")
            return
        }

        if (clipUri != null) {
            isFile = true
            fileUri = clipUri
        } else {
            isFile = false
            inputText = clipText
        }

        askForCipher { cipherChosen ->
            selectedCipher = cipherChosen
            askForKey { key ->
                if (isFile) {
                    encryptFile(fileUri!!, key, selectedCipher)
                } else {
                    encryptText(inputText!!, key, selectedCipher)
                }
            }
        }
    }

    private fun askForCipher(onCipherSelected: (String) -> Unit) {
        val ciphers = arrayOf("AES","DES","CAMELLIA","CHACHA20POLY1305","XCHACHA20POLY1305","AEGIS256")
        AlertDialog.Builder(this)
            .setTitle("Choose Cipher")
            .setItems(ciphers) { _, which ->
                onCipherSelected(ciphers[which])
            }
            .setOnCancelListener { finish() }
            .show()
    }

    private fun askForKey(onKeyEntered: (String) -> Unit) {
        val keyItems = KeysRepository.loadKeys(this)
        if (keyItems.isEmpty()) {
            askKeyManually(onKeyEntered)
        } else {
            val nicknames = keyItems.map { it.nickname }.toMutableList()
            val addNew = "Enter a new key..."
            nicknames.add(addNew)

            AlertDialog.Builder(this)
                .setTitle("Choose a key")
                .setItems(nicknames.toTypedArray()) { _, which ->
                    val selected = nicknames[which]
                    if (selected == addNew) {
                        askKeyManually(onKeyEntered)
                    } else {
                        val item = keyItems.find { it.nickname == selected }
                        if (item != null) onKeyEntered(item.secret)
                        else askKeyManually(onKeyEntered)
                    }
                }
                .setOnCancelListener { finish() }
                .show()
        }
    }

    private fun askKeyManually(callback: (String) -> Unit) {
        val edit = EditText(this)
        edit.hint = "Enter encryption key"

        AlertDialog.Builder(this)
            .setTitle("Enter Key")
            .setView(edit)
            .setPositiveButton("OK") { _, _ ->
                val key = edit.text.toString().trim()
                if (key.isNotEmpty()) {
                    callback(key)
                } else {
                    showFinalDialog("Empty key.")
                }
            }
            .setNegativeButton("Cancel") { _, _ ->
                finish()
            }
            .show()
    }

    private fun encryptText(plainText: String, key: String, cipher: String) {
        val result = try {
            when (cipher) {
                "AES" -> EncryptDecryptHelper.encryptAES(plainText, key)
                "DES" -> EncryptDecryptHelper.encryptDES(plainText, key)
                "CAMELLIA" -> EncryptDecryptHelper.encryptCamellia(plainText, key)
                "CHACHA20POLY1305" -> EncryptDecryptHelper.encryptChaCha20Poly1305(plainText, key)
                "XCHACHA20POLY1305" -> EncryptDecryptHelper.encryptXChaCha20Poly1305(plainText, key)
                "AEGIS256" -> EncryptDecryptHelper.encryptAegis256(plainText, key)
                else -> "Error: cipher not implemented"
            }
        } catch (ex: Exception) {
            ex.printStackTrace()
            "Error encrypting text: ${ex.message}"
        }
        showFinalDialog(result)
    }

    /**
     * Archivos: se procesan POR FLUJO (sin cargar el archivo en memoria, funciona con archivos
     * de cientos de MB) y el destino se elige con el diálogo del sistema "Guardar como".
     */
    private fun encryptFile(uri: Uri, key: String, cipher: String) {
        pendingKey = key
        pendingCipher = cipher
        val originalName = FileHelper.getFilenameFromUri(this, uri) ?: "file"
        saveAsLauncher.launch(FileHelper.outputName(originalName, true))
    }

    private fun onSaveTargetChosen(outUri: Uri?) {
        val inUri = fileUri
        val key = pendingKey
        pendingKey = null
        if (outUri == null || inUri == null || key == null) {
            showFinalDialog("Cancelled. Nothing was saved.")
            return
        }

        val total = FileHelper.getFileSize(this, inUri)
        progressDialog = AlertDialog.Builder(this)
            .setTitle("Encrypting...")
            .setMessage("Working...")
            .setCancelable(false)
            .setNegativeButton("Cancel") { _, _ -> job?.cancel() }
            .show()

        job = FileCryptoRunner.start(
            context = this,
            encrypt = true,
            cipher = pendingCipher,
            password = key,
            inUri = inUri,
            outUri = outUri,
            totalBytes = total,
            onProgress = { done, t ->
                if (!isDestroyed) {
                    progressDialog?.setMessage(
                        if (t > 0) "${FileHelper.formatSize(done)} of ${FileHelper.formatSize(t)} (${(done * 100 / t).coerceIn(0, 100)}%)"
                        else "Processed ${FileHelper.formatSize(done)}"
                    )
                }
            },
            onResult = { result ->
                job = null
                if (!isDestroyed) {
                    handleFileResult(result, outUri)
                }
            }
        )
    }

    private fun handleFileResult(result: FileCryptoRunner.Result, outUri: Uri) {
        progressDialog?.dismiss()
        progressDialog = null
        when (result) {
            is FileCryptoRunner.Result.Success -> {
                val name = FileHelper.getFilenameFromUri(this, outUri) ?: "file"
                showFinalDialog("File encrypted successfully.\nSaved as: $name\n${Uri.decode(outUri.toString())}")
            }
            is FileCryptoRunner.Result.Cancelled ->
                showFinalDialog("Cancelled. Nothing was saved.")
            is FileCryptoRunner.Result.Failure ->
                showFinalDialog("Error: ${result.message}")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (isFinishing) job?.cancel()
        progressDialog?.dismiss()
    }

    // CAMBIADO: 2 botones => "Copy" y "Close"
    private fun showFinalDialog(msg: String) {
        AlertDialog.Builder(this)
            .setTitle("Encrypt Share")
            .setMessage(ClipboardHelper.preview(msg))
            .setPositiveButton("Copy") { _, _ ->
                if (ClipboardHelper.copy(this, "EncryptedResult", msg)) {
                    Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, ClipboardHelper.tooLargeMessage(msg), Toast.LENGTH_LONG).show()
                }
                finish()
            }
            .setNegativeButton("Close") { _, _ -> finish() }
            .setOnDismissListener { finish() }
            .show()
    }

    private fun copyToClipboard(text: String) {
        val cb = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("EncryptedText", text)
        cb.setPrimaryClip(clip)
    }
}
