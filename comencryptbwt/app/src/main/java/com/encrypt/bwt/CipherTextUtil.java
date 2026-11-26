// CipherTextUtil.java
package com.encrypt.bwt;

import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;

/**
 * Разбор Base64-шифртекста, устойчивый к тому, что с ним делают при копировании
 * (переносы строк, пробелы, кавычки, URL-safe алфавит, потерянное «=»),
 * и понятные сообщения об ошибках расшифровки (вместо общего "Error decrypting text.").
 *
 * Без зависимостей от android.* -> проверяется на обычной JVM.
 */
public final class CipherTextUtil {

    private CipherTextUtil() {
    }

    /** Декодирует шифртекст; бросает IllegalArgumentException с понятным текстом. */
    public static byte[] decode(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Encrypted text is empty.");
        }
        StringBuilder sb = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (Character.isWhitespace(c) || Character.isSpaceChar(c)
                    || c == '​' || c == '‌' || c == '‍' || c == '⁠' || c == '﻿') {
                continue; // переносы строк, пробелы, невидимые символы
            }
            if (c == '-') c = '+'; // URL-safe -> стандартный алфавит
            else if (c == '_') c = '/';
            sb.append(c);
        }
        // Кавычки/обратные апострофы по краям (копирование из мессенджеров, markdown)
        int start = 0;
        int end = sb.length();
        while (start < end && isWrapper(sb.charAt(start))) start++;
        while (end > start && isWrapper(sb.charAt(end - 1))) end--;
        String s = sb.substring(start, end);

        // Отбрасываем '=' в конце и дополним заново: некоторые приложения их «съедают»
        int len = s.length();
        while (len > 0 && s.charAt(len - 1) == '=') len--;
        s = s.substring(0, len);

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '+' || c == '/';
            if (!ok) {
                throw new IllegalArgumentException("Encrypted text contains an invalid character '"
                        + c + "' at position " + (i + 1) + ". The text was probably changed while copying. "
                        + "Copy the whole encrypted text again.");
            }
        }
        if (s.isEmpty()) {
            throw new IllegalArgumentException("Encrypted text is empty.");
        }
        if (s.length() % 4 == 1) {
            throw new IllegalArgumentException("Encrypted text is incomplete (" + s.length()
                    + " characters, the end was cut off). Copy the whole text again.");
        }
        StringBuilder padded = new StringBuilder(s);
        while (padded.length() % 4 != 0) padded.append('=');
        return Base64.getDecoder().decode(padded.toString());
    }

    private static boolean isWrapper(char c) {
        return c == '"' || c == '\'' || c == '`' || c == '“' || c == '”'
                || c == '‘' || c == '’' || c == '«' || c == '»';
    }

    /** Понятное сообщение для пользователя, когда расшифровка не удалась. */
    public static String explainDecryptFailure(Throwable t, String cipherText) {
        int n = cipherText == null ? 0 : cipherText.length();
        if (t instanceof IllegalArgumentException && t.getMessage() != null
                && t.getMessage().startsWith("Encrypted text")) {
            return t.getMessage();
        }
        if (t instanceof AEADBadTagException || t instanceof BadPaddingException
                || t instanceof InvalidCipherTextException
                || t instanceof com.encrypt.bwt.aegis.VerificationFailedException) {
            return "Decryption failed: wrong key, wrong algorithm, or the encrypted text is "
                    + "incomplete/changed (" + n + " characters were received). "
                    + "Check the key and the selected algorithm; if the text is long, make sure it was copied completely.";
        }
        if (t instanceof IllegalArgumentException) {
            return "Invalid encrypted text: " + (t.getMessage() == null ? "bad format" : t.getMessage());
        }
        if (t instanceof OutOfMemoryError) {
            return "Not enough memory for such a large text. Use FILE ENCRYPTION for big data.";
        }
        return "Decryption error: " + (t.getMessage() == null ? t.getClass().getSimpleName() : t.getMessage());
    }
}
