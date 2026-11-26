// CreateAnyDocument.kt
package com.encrypt.bwt

import android.content.Context
import android.content.Intent
import androidx.activity.result.contract.ActivityResultContracts

/**
 * Diálogo del sistema "Guardar como" (ACTION_CREATE_DOCUMENT).
 * Permite elegir CUALQUIER ubicación (incluida la raíz del almacenamiento interno,
 * Descargas, tarjeta SD...) y pulsar "Guardar", a diferencia de ACTION_OPEN_DOCUMENT_TREE,
 * que en Android 11+ prohíbe seleccionar la raíz y carpetas como Download.
 *
 * El MIME se deduce de la extensión del nombre para que Android no le añada ".bin".
 */
class CreateAnyDocument : ActivityResultContracts.CreateDocument("application/octet-stream") {
    override fun createIntent(context: Context, input: String): Intent {
        val intent = super.createIntent(context, input)
        intent.type = FileHelper.guessMimeType(input)
        return intent
    }
}
