// StreamCrypto.java
package com.encrypt.bwt;

import com.encrypt.bwt.aegis.Aegis256;
import com.encrypt.bwt.aegis.VerificationFailedException;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Cifrado/descifrado de ARCHIVOS por flujo (streaming), sin cargar el archivo en memoria.
 *
 * El formato de salida es EXACTAMENTE el mismo que el de las funciones
 * EncryptDecryptHelper.encryptBytesXxx / decryptBytesXxx, por lo que:
 *   - los archivos cifrados con versiones anteriores de la app se pueden descifrar con esta clase;
 *   - los archivos cifrados con esta clase se pueden descifrar con las versiones anteriores.
 *
 *   AES / CAMELLIA (GCM) : SALT(16) | IV(12)    | ciphertext | tag(16)
 *   CHACHA20POLY1305     : SALT(16) | NONCE(12) | ciphertext | tag(16)
 *   XCHACHA20POLY1305    : SALT(16) | NONCE(24) | ciphertext | tag(16)
 *   AEGIS256             : SALT(16) | NONCE(32) | ciphertext | tag(16)
 *   DES (legado, ECB)    : ciphertext (PKCS5)
 *
 * Esta clase no depende de android.* para poder probarse en una JVM normal.
 */
public final class StreamCrypto {

    /** Callback de progreso / cancelación. Se invoca desde el hilo que cifra. */
    public interface Listener {
        /** @param bytesRead bytes de entrada procesados hasta ahora. */
        void onProgress(long bytesRead);

        boolean isCancelled();
    }

    public static final class CancelledException extends IOException {
        public CancelledException() {
            super("Cancelled");
        }
    }

    private static final int CHUNK = 64 * 1024;            // múltiplo de 16
    private static final int SALT_SIZE = 16;
    private static final int PBKDF2_ITERATIONS = 100_000;  // igual que EncryptDecryptHelper
    private static final int KEY_BITS = 256;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RNG = new SecureRandom();

    private StreamCrypto() {
    }

    // ---------------------------------------------------------------- API pública

    public static void encrypt(String cipher, String password, InputStream in, OutputStream out,
                               Listener l) throws Exception {
        switch (cipher) {
            case "AES":
                aeadEncrypt(false, password, 12, in, out, l, key -> gcm(AESEngine.newInstance()));
                break;
            case "CAMELLIA":
                aeadEncrypt(false, password, 12, in, out, l, key -> gcm(new CamelliaEngine()));
                break;
            case "CHACHA20POLY1305":
                aeadEncrypt(false, password, 12, in, out, l, key -> new ChaCha20Poly1305());
                break;
            case "XCHACHA20POLY1305":
                aeadEncrypt(true, password, 24, in, out, l, null);
                break;
            case "AEGIS256":
                aegisEncrypt(password, in, out, l);
                break;
            case "DES":
                desProcess(true, password, in, out, l);
                break;
            default:
                throw new IllegalArgumentException("Cipher not implemented: " + cipher);
        }
        out.flush();
    }

    public static void decrypt(String cipher, String password, InputStream in, OutputStream out,
                               Listener l) throws Exception {
        switch (cipher) {
            case "AES":
                aeadDecrypt(false, password, 12, in, out, l, key -> gcm(AESEngine.newInstance()));
                break;
            case "CAMELLIA":
                aeadDecrypt(false, password, 12, in, out, l, key -> gcm(new CamelliaEngine()));
                break;
            case "CHACHA20POLY1305":
                aeadDecrypt(false, password, 12, in, out, l, key -> new ChaCha20Poly1305());
                break;
            case "XCHACHA20POLY1305":
                aeadDecrypt(true, password, 24, in, out, l, null);
                break;
            case "AEGIS256":
                aegisDecrypt(password, in, out, l);
                break;
            case "DES":
                desProcess(false, password, in, out, l);
                break;
            default:
                throw new IllegalArgumentException("Cipher not implemented: " + cipher);
        }
        out.flush();
    }

    // ---------------------------------------------------------------- AEAD (GCM / ChaCha)

    private interface CipherFactory {
        AEADCipher create(byte[] key);
    }

    private static AEADCipher gcm(BlockCipher engine) {
        return new GCMBlockCipher(engine);
    }

    private static void aeadEncrypt(boolean xchacha, String password, int nonceLen,
                                    InputStream in, OutputStream out, Listener l,
                                    CipherFactory factory) throws Exception {
        byte[] salt = random(SALT_SIZE);
        byte[] nonce = random(nonceLen);
        byte[] key = deriveKey(password, salt);

        AEADCipher c = xchacha
                ? XChaCha20Poly1305.newStreamCipher(key, nonce, true)
                : initAead(factory.create(key), key, nonce, true);

        out.write(salt);
        out.write(nonce);
        pumpAead(c, in, out, l);
    }

    private static void aeadDecrypt(boolean xchacha, String password, int nonceLen,
                                    InputStream in, OutputStream out, Listener l,
                                    CipherFactory factory) throws Exception {
        byte[] salt = new byte[SALT_SIZE];
        byte[] nonce = new byte[nonceLen];
        readHeader(in, salt);
        readHeader(in, nonce);
        byte[] key = deriveKey(password, salt);

        AEADCipher c = xchacha
                ? XChaCha20Poly1305.newStreamCipher(key, nonce, false)
                : initAead(factory.create(key), key, nonce, false);

        pumpAead(c, in, out, l);
    }

    private static AEADCipher initAead(AEADCipher c, byte[] key, byte[] nonce, boolean enc) {
        c.init(enc, new AEADParameters(new KeyParameter(key), TAG_BITS, nonce, new byte[0]));
        return c;
    }

    private static void pumpAead(AEADCipher c, InputStream in, OutputStream out, Listener l)
            throws Exception {
        byte[] inBuf = new byte[CHUNK];
        byte[] outBuf = new byte[CHUNK + 64];
        long total = 0;
        int n;
        while ((n = in.read(inBuf)) != -1) {
            checkCancel(l);
            int need = c.getUpdateOutputSize(n);
            if (need > outBuf.length) {
                outBuf = new byte[need];
            }
            int w = c.processBytes(inBuf, 0, n, outBuf, 0);
            if (w > 0) {
                out.write(outBuf, 0, w);
            }
            total += n;
            progress(l, total);
        }
        checkCancel(l);
        int need = c.getOutputSize(0);
        if (need > outBuf.length) {
            outBuf = new byte[need];
        }
        // En descifrado lanza InvalidCipherTextException si el tag no coincide.
        int w = c.doFinal(outBuf, 0);
        if (w > 0) {
            out.write(outBuf, 0, w);
        }
        progress(l, total);
    }

    // ---------------------------------------------------------------- AEGIS-256

    private static void aegisEncrypt(String password, InputStream in, OutputStream out, Listener l)
            throws Exception {
        byte[] salt = random(SALT_SIZE);
        byte[] nonce = random(32);
        byte[] key = deriveKey(password, salt);
        Aegis256 aegis = new Aegis256(key, nonce, 16);

        out.write(salt);
        out.write(nonce);

        byte[] inBuf = new byte[CHUNK];
        byte[] outBuf = new byte[CHUNK];
        long total = 0;
        while (true) {
            checkCancel(l);
            int n = readChunk(in, inBuf);
            if (n <= 0) {
                break;
            }
            aegis.streamEncrypt(inBuf, 0, n, outBuf, 0);
            out.write(outBuf, 0, n);
            total += n;
            progress(l, total);
            if (n < CHUNK) {
                break;
            }
        }
        out.write(aegis.streamFinish(total));
        progress(l, total);
    }

    private static void aegisDecrypt(String password, InputStream in, OutputStream out, Listener l)
            throws Exception {
        byte[] salt = new byte[SALT_SIZE];
        byte[] nonce = new byte[32];
        readHeader(in, salt);
        readHeader(in, nonce);
        byte[] key = deriveKey(password, salt);
        Aegis256 aegis = new Aegis256(key, nonce, 16);

        final int tagLen = 16;
        byte[] buf = new byte[CHUNK + tagLen + 16];
        byte[] outBuf = new byte[CHUNK + tagLen + 16];
        int filled = 0;
        long msgLen = 0;
        long read = 0;

        while (true) {
            checkCancel(l);
            int r = in.read(buf, filled, buf.length - filled);
            if (r < 0) {
                break;
            }
            filled += r;
            read += r;
            // Siempre retenemos los últimos 16 bytes (posible tag) y procesamos solo bloques completos.
            int avail = filled - tagLen;
            int proc = avail > 0 ? avail - (avail % 16) : 0;
            if (proc > 0) {
                aegis.streamDecrypt(buf, 0, proc, outBuf, 0);
                out.write(outBuf, 0, proc);
                msgLen += proc;
                System.arraycopy(buf, proc, buf, 0, filled - proc);
                filled -= proc;
            }
            progress(l, read);
        }

        if (filled < tagLen) {
            throw new IllegalArgumentException("Invalid Aegis256 data (truncated)");
        }
        int ctRem = filled - tagLen;
        if (ctRem > 0) {
            aegis.streamDecrypt(buf, 0, ctRem, outBuf, 0);
            out.write(outBuf, 0, ctRem);
            msgLen += ctRem;
        }
        byte[] expected = Arrays.copyOfRange(buf, ctRem, filled);
        byte[] actual = aegis.streamFinish(msgLen);
        if (!Aegis256.tagEquals(expected, actual)) {
            throw new VerificationFailedException("verification failed");
        }
    }

    // ---------------------------------------------------------------- DES (legado)

    private static void desProcess(boolean enc, String password, InputStream in, OutputStream out,
                                   Listener l) throws Exception {
        byte[] keyBytes = Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 8);
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(enc ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "DES"));

        byte[] inBuf = new byte[CHUNK];
        byte[] outBuf = new byte[CHUNK + 16];
        long total = 0;
        int n;
        while ((n = in.read(inBuf)) != -1) {
            checkCancel(l);
            int w = c.update(inBuf, 0, n, outBuf, 0);
            if (w > 0) {
                out.write(outBuf, 0, w);
            }
            total += n;
            progress(l, total);
        }
        byte[] last = c.doFinal();
        if (last != null && last.length > 0) {
            out.write(last);
        }
        progress(l, total);
    }

    // ---------------------------------------------------------------- utilidades

    static byte[] deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_BITS);
        return f.generateSecret(spec).getEncoded();
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    private static void readHeader(InputStream in, byte[] dst) throws IOException {
        int off = 0;
        while (off < dst.length) {
            int r = in.read(dst, off, dst.length - off);
            if (r < 0) {
                throw new IllegalArgumentException(
                        "Invalid data: file is too short or was not encrypted with this cipher");
            }
            off += r;
        }
    }

    /** Lee hasta llenar el buffer o hasta EOF. Devuelve los bytes leídos (0 si EOF inmediato). */
    private static int readChunk(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int r = in.read(buf, off, buf.length - off);
            if (r < 0) {
                break;
            }
            off += r;
        }
        return off;
    }

    private static void checkCancel(Listener l) throws CancelledException {
        if (l != null && l.isCancelled()) {
            throw new CancelledException();
        }
    }

    private static void progress(Listener l, long bytes) {
        if (l != null) {
            l.onProgress(bytes);
        }
    }
}
