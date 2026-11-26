// ClipboardHelper.kt
package com.encrypt.bwt

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent

/**
 * Безопасная работа с буфером обмена и большим текстом.
 *  - setPrimaryClip для очень большого текста (> ~1 МБ по Binder) бросает исключение
 *    (TransactionTooLargeException) и раньше приложение падало.
 *  - AlertDialog с сотнями тысяч символов в setMessage тормозит/зависает, поэтому показываем превью.
 */
object ClipboardHelper {

    private const val PREVIEW_THRESHOLD = 20_000
    private const val PREVIEW_CHARS = 2_000

    /** true, если текст скопирован. */
    fun copy(context: Context, label: String, text: String): Boolean {
        return try {
            val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText(label, text))
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    fun tooLargeMessage(text: String): String =
        "The text (${text.length} characters) is too large for the clipboard. " +
            "Use FILE ENCRYPTION for big data."

    /** Короткая версия для показа в диалоге; полный текст копируется кнопкой Copy. */
    fun preview(text: String): String {
        if (text.length <= PREVIEW_THRESHOLD) return text
        return text.take(PREVIEW_CHARS) +
            "\n\n... [${text.length} characters in total, only the first $PREVIEW_CHARS are shown. " +
            "Press Copy to get the full text.]"
    }
}

/**
 * Большой выделенный текст нельзя класть в Intent/PendingIntent (лимит Binder ~1 МБ,
 * иначе TransactionTooLargeException), поэтому он передаётся через память процесса.
 */
object SelectedTextStore {
    const val EXTRA_TEXT = "EXTRA_SELECTED_TEXT"
    const val EXTRA_STORED = "EXTRA_SELECTED_TEXT_STORED"
    private const val INLINE_LIMIT = 20_000

    @Volatile
    private var stored: String? = null

    /** Кладёт текст в Intent напрямую или, если он большой, в хранилище. */
    fun attach(intent: Intent, text: String) {
        if (text.length > INLINE_LIMIT) {
            stored = text
            intent.putExtra(EXTRA_STORED, true)
        } else {
            intent.putExtra(EXTRA_TEXT, text)
        }
    }

    fun read(intent: Intent?): String {
        if (intent == null) return ""
        if (intent.getBooleanExtra(EXTRA_STORED, false)) return stored.orEmpty()
        return intent.getCharSequenceExtra(EXTRA_TEXT)?.toString().orEmpty()
    }

    fun clear() {
        stored = null
    }
}
