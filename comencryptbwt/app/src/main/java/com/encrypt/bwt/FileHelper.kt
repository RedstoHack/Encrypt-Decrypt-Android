//FileHelper.kt
package com.encrypt.bwt

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import androidx.documentfile.provider.DocumentFile

object FileHelper {

    /**
     * Lee todos los bytes de un Uri (archivo).
     * Retorna null si falla.
     */
    fun readAllBytesFromUri(context: Context, uri: Uri): ByteArray? {
        return try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                input.readBytes()
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Escribe [data] en [uri].
     * Retorna true si OK, false si error.
     */
    fun writeAllBytesToUri(context: Context, uri: Uri, data: ByteArray): Boolean {
        return try {
            context.contentResolver.openOutputStream(uri)?.use { output ->
                output.write(data)
                output.flush()
            }
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    /**
     * Intenta obtener el nombre (filename) del Uri,
     * por ejemplo "miFoto.jpg".
     */
    fun getFilenameFromUri(context: Context, uri: Uri): String? {
        var result: String? = null
        if (uri.scheme == ContentResolver.SCHEME_CONTENT) {
            val cursor = context.contentResolver.query(uri, null, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val idx = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) {
                        result = it.getString(idx)
                    }
                }
            }
        }
        if (result == null) {
            result = uri.lastPathSegment
        }
        return result
    }

    /**
     * Tamaño del archivo en bytes, o -1 si el proveedor no lo informa.
     */
    fun getFileSize(context: Context, uri: Uri): Long {
        return try {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)
                ?.use { c ->
                    if (c.moveToFirst() && !c.isNull(0)) c.getLong(0) else -1L
                } ?: -1L
        } catch (e: Exception) {
            -1L
        }
    }

    /**
     * Nombre sugerido para el archivo de salida.
     *  - cifrar:    "foto.jpg"       -> "foto.jpg.encrypted"
     *  - descifrar: "foto.jpg.encrypted" -> "foto.jpg"  (si no termina en .encrypted: "<nombre>.decrypted")
     */
    fun outputName(originalName: String, encrypt: Boolean): String {
        return if (encrypt) {
            "$originalName.encrypted"
        } else if (originalName.endsWith(".encrypted", ignoreCase = true)) {
            originalName.dropLast(".encrypted".length).ifEmpty { "file.decrypted" }
        } else {
            "$originalName.decrypted"
        }
    }

    /**
     * MIME según la extensión del nombre (application/octet-stream si se desconoce).
     * Importante: si se crea "foto.jpg" con MIME octet-stream, Android le añade ".bin".
     */
    fun guessMimeType(fileName: String): String {
        val ext = fileName.substringAfterLast('.', "").lowercase()
        if (ext.isEmpty()) return "application/octet-stream"
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
    }

    /**
     * Crea (sobrescribiendo si existe) un archivo vacío dentro de la carpeta [treeUri]
     * elegida con ACTION_OPEN_DOCUMENT_TREE. Devuelve null si la carpeta no es válida.
     */
    fun createFileInTree(context: Context, treeUri: Uri, name: String): Uri? {
        return try {
            val dir = DocumentFile.fromTreeUri(context, treeUri) ?: return null
            if (!dir.isDirectory || !dir.canWrite()) return null
            dir.findFile(name)?.delete()
            dir.createFile(guessMimeType(name), name)?.uri
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /** Borra un documento ignorando cualquier error (p. ej. salida parcial tras un fallo). */
    fun deleteQuietly(context: Context, uri: Uri) {
        try {
            DocumentFile.fromSingleUri(context, uri)?.delete()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    /** "12.3 MB" */
    fun formatSize(bytes: Long): String {
        if (bytes < 1024) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var v = bytes.toDouble() / 1024.0
        var i = 0
        while (v >= 1024.0 && i < units.size - 1) {
            v /= 1024.0
            i++
        }
        return String.format(java.util.Locale.US, "%.1f %s", v, units[i])
    }
}
