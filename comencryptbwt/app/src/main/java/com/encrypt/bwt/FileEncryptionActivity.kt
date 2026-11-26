//FileEncryptionActivity
package com.encrypt.bwt

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.widget.*
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

class FileEncryptionActivity : AppCompatActivity() {

    private lateinit var radioEncrypt: RadioButton
    private lateinit var radioDecrypt: RadioButton
    private lateinit var textSelectedFile: TextView
    private lateinit var spinnerCipher: Spinner
    private lateinit var buttonPickKey: Button
    private lateinit var textChosenKey: TextView
    private lateinit var buttonPickFile: Button
    private lateinit var buttonPickFolder: Button
    private lateinit var buttonClearFolder: Button
    private lateinit var buttonProcess: Button
    private lateinit var buttonCancel: Button
    private lateinit var textResult: TextView
    private lateinit var textOutputDir: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var textProgress: TextView

    private var selectedFileUri: Uri? = null
    private var selectedCipher: String = "AES"
    private var chosenKey: String? = null
    private var customOutputUri: Uri? = null   // carpeta elegida por el usuario (opcional)

    // Parámetros de la operación pendiente mientras se muestra el diálogo "Guardar como"
    private var pendingEncrypt = true
    private var pendingCipher = "AES"
    private var pendingKey: String? = null
    private var pendingInput: Uri? = null

    private var job: FileCryptoRunner.Job? = null

    private lateinit var pickFileLauncher: ActivityResultLauncher<Array<String>>
    private lateinit var pickFolderLauncher: ActivityResultLauncher<Uri?>
    private lateinit var saveAsLauncher: ActivityResultLauncher<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_file_encryption)

        // Referencias
        radioEncrypt = findViewById(R.id.radioEncrypt)
        radioDecrypt = findViewById(R.id.radioDecrypt)
        textSelectedFile = findViewById(R.id.textSelectedFile)
        spinnerCipher = findViewById(R.id.spinnerCipher)
        buttonPickKey = findViewById(R.id.buttonPickKey)
        textChosenKey = findViewById(R.id.textChosenKey)
        buttonPickFile = findViewById(R.id.buttonPickFile)
        buttonPickFolder = findViewById(R.id.buttonPickOutputDir)
        buttonClearFolder = findViewById(R.id.buttonClearOutputDir)
        buttonProcess = findViewById(R.id.buttonProcess)
        buttonCancel = findViewById(R.id.buttonCancel)
        textResult = findViewById(R.id.textResult)
        textOutputDir = findViewById(R.id.textOutputDir)
        progressBar = findViewById(R.id.progressBar)
        textProgress = findViewById(R.id.textProgress)

        // Spinner de algoritmos (texto blanco explícito: se ve en cualquier tema del sistema)
        val ciphers = arrayOf("AES", "DES", "CAMELLIA", "CHACHA20POLY1305", "XCHACHA20POLY1305", "AEGIS256")
        val adapter = ArrayAdapter(this, R.layout.spinner_item, ciphers)
        adapter.setDropDownViewResource(R.layout.spinner_dropdown_item)
        spinnerCipher.adapter = adapter
        spinnerCipher.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                selectedCipher = ciphers[position]
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // Cargar carpeta elegida anteriormente (SharedPreferences)
        val prefs = getSharedPreferences("FileEncPrefs", MODE_PRIVATE)
        prefs.getString("customOutputUri", null)?.let {
            customOutputUri = Uri.parse(it)
        }
        refreshOutputDirUi()

        // 1) Elegir archivo de entrada
        pickFileLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
            if (uri != null) {
                try {
                    contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                } catch (e: Exception) {
                    // Algunos proveedores no permiten permisos persistentes; no es necesario para esta sesión.
                }
                selectedFileUri = uri
                val name = FileHelper.getFilenameFromUri(this, uri) ?: uri.toString()
                val size = FileHelper.getFileSize(this, uri)
                textSelectedFile.text = if (size >= 0) "$name  (${FileHelper.formatSize(size)})" else name
            }
        }

        // 2) Carpeta de salida (opcional)
        pickFolderLauncher = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
            if (uri != null) {
                try {
                    contentResolver.takePersistableUriPermission(
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    )
                } catch (e: Exception) {
                    e.printStackTrace()
                }
                customOutputUri = uri
                getSharedPreferences("FileEncPrefs", MODE_PRIVATE)
                    .edit().putString("customOutputUri", uri.toString()).apply()
                refreshOutputDirUi()
            }
        }

        // 3) Diálogo del sistema "Guardar como": cualquier ubicación + botón "Guardar"
        saveAsLauncher = registerForActivityResult(CreateAnyDocument()) { outUri: Uri? ->
            val input = pendingInput
            val key = pendingKey
            if (outUri == null || input == null || key == null) {
                showMessage("Cancelled. Nothing was saved.")
            } else {
                startJob(pendingEncrypt, pendingCipher, key, input, outUri)
            }
            pendingKey = null
            pendingInput = null
        }

        // Botones
        buttonPickFile.setOnClickListener { pickFileLauncher.launch(arrayOf("*/*")) }
        buttonPickFolder.setOnClickListener { pickFolderLauncher.launch(null) }
        buttonClearFolder.setOnClickListener {
            customOutputUri = null
            getSharedPreferences("FileEncPrefs", MODE_PRIVATE).edit().remove("customOutputUri").apply()
            refreshOutputDirUi()
        }
        buttonPickKey.setOnClickListener {
            askForKey { key ->
                chosenKey = key
                textChosenKey.text = "(Key chosen: ${key.take(6)}...)"
            }
        }
        buttonProcess.setOnClickListener { doProcess() }
        buttonCancel.setOnClickListener {
            job?.cancel()
            buttonCancel.isEnabled = false
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Si el usuario sale de la pantalla, se cancela y se borra la salida parcial.
        if (isFinishing) job?.cancel()
    }

    private fun refreshOutputDirUi() {
        val uri = customOutputUri
        if (uri == null) {
            textOutputDir.text = "No folder selected. After EXECUTE you will choose where to save the file."
            buttonClearFolder.visibility = View.GONE
        } else {
            textOutputDir.text = "Chosen Folder:\n${Uri.decode(uri.toString())}"
            buttonClearFolder.visibility = View.VISIBLE
        }
    }

    private fun doProcess() {
        if (job != null) return
        textResult.visibility = View.GONE

        val inUri = selectedFileUri
        if (inUri == null) {
            showMessage("No file selected.")
            return
        }
        val key = chosenKey
        if (key.isNullOrEmpty()) {
            showMessage("No key chosen.")
            return
        }

        val encrypt = radioEncrypt.isChecked
        val cipher = selectedCipher
        val originalName = FileHelper.getFilenameFromUri(this, inUri) ?: "file"
        val outName = FileHelper.outputName(originalName, encrypt)

        // Si el usuario eligió una carpeta, se guarda ahí directamente.
        val folder = customOutputUri
        if (folder != null) {
            val outUri = FileHelper.createFileInTree(this, folder, outName)
            if (outUri != null) {
                startJob(encrypt, cipher, key, inUri, outUri)
                return
            }
            Toast.makeText(
                this,
                "The saved folder is not available any more. Choose where to save.",
                Toast.LENGTH_LONG
            ).show()
        }

        // Si no: "Guardar como" del sistema (permite elegir la raíz del almacenamiento, Descargas, etc.)
        pendingEncrypt = encrypt
        pendingCipher = cipher
        pendingKey = key
        pendingInput = inUri
        saveAsLauncher.launch(outName)
    }

    private fun startJob(encrypt: Boolean, cipher: String, key: String, inUri: Uri, outUri: Uri) {
        val total = FileHelper.getFileSize(this, inUri)
        setBusy(true, total)

        job = FileCryptoRunner.start(
            context = this,
            encrypt = encrypt,
            cipher = cipher,
            password = key,
            inUri = inUri,
            outUri = outUri,
            totalBytes = total,
            onProgress = { done, t -> if (!isDestroyed) updateProgress(done, t) },
            onResult = { result ->
                job = null
                if (!isDestroyed) {
                    handleResult(result, encrypt, outUri, total)
                }
            }
        )
    }

    private fun handleResult(result: FileCryptoRunner.Result, encrypt: Boolean, outUri: Uri, total: Long) {
        setBusy(false, total)
        when (result) {
            is FileCryptoRunner.Result.Success -> {
                val name = FileHelper.getFilenameFromUri(this, outUri) ?: "file"
                showMessage(
                    (if (encrypt) "Encrypted successfully." else "Decrypted successfully.") +
                        "\nSaved as: $name\n${Uri.decode(outUri.toString())}"
                )
            }
            is FileCryptoRunner.Result.Cancelled ->
                showMessage("Cancelled. Nothing was saved.")
            is FileCryptoRunner.Result.Failure ->
                showMessage("Error: ${result.message}")
        }
    }

    private fun setBusy(busy: Boolean, total: Long) {
        val controls = listOf(
            buttonProcess, buttonPickFile, buttonPickKey, buttonPickFolder, buttonClearFolder,
            radioEncrypt, radioDecrypt, spinnerCipher
        )
        controls.forEach { it.isEnabled = !busy }
        if (busy) {
            progressBar.isIndeterminate = total <= 0
            progressBar.progress = 0
            progressBar.visibility = View.VISIBLE
            textProgress.text = "Working..."
            textProgress.visibility = View.VISIBLE
            buttonCancel.isEnabled = true
            buttonCancel.visibility = View.VISIBLE
            // Pantalla encendida mientras se procesa un archivo grande
            window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        } else {
            progressBar.visibility = View.GONE
            textProgress.visibility = View.GONE
            buttonCancel.visibility = View.GONE
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
    }

    private fun updateProgress(done: Long, total: Long) {
        if (total > 0) {
            val permille = ((done * 1000L) / total).toInt().coerceIn(0, 1000)
            progressBar.progress = permille
            textProgress.text =
                "${FileHelper.formatSize(done)} of ${FileHelper.formatSize(total)} (${permille / 10}%)"
        } else {
            textProgress.text = "Processed ${FileHelper.formatSize(done)}"
        }
    }

    private fun askForKey(onKeyEntered: (String) -> Unit) {
        val keyItems = KeysRepository.loadKeys(this)
        if (keyItems.isEmpty()) {
            askKeyManual(onKeyEntered)
        } else {
            val nicks = keyItems.map { it.nickname }.toMutableList()
            val addNew = "Enter new key..."
            nicks.add(addNew)
            AlertDialog.Builder(this)
                .setTitle("Choose Key")
                .setItems(nicks.toTypedArray()) { _, which ->
                    val sel = nicks[which]
                    if (sel == addNew) {
                        askKeyManual(onKeyEntered)
                    } else {
                        val item = keyItems.find { it.nickname == sel }
                        if (item != null) onKeyEntered(item.secret)
                        else askKeyManual(onKeyEntered)
                    }
                }
                .show()
        }
    }

    private fun askKeyManual(callback: (String) -> Unit) {
        val edt = EditText(this)
        edt.hint = "Enter key"
        AlertDialog.Builder(this)
            .setTitle("Manual Key")
            .setView(edt)
            .setPositiveButton("OK") { _, _ ->
                val k = edt.text.toString().trim()
                if (k.isNotEmpty()) {
                    callback(k)
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showMessage(msg: String) {
        textResult.visibility = View.VISIBLE
        textResult.text = msg
    }
}
