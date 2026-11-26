package com.encrypt.bwt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.encrypt.bwt.aegis.Aegis256;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pruebas de StreamCrypto (cifrado de archivos por flujo):
 *  - ida y vuelta para todos los algoritmos y tamaños límite (bloques de 16 / chunks de 64 KiB);
 *  - compatibilidad con el formato "SALT | IV | ciphertext | tag" de las versiones anteriores;
 *  - clave incorrecta / datos manipulados / truncados => error.
 */
public class StreamCryptoTest {

    private static final String[] CIPHERS = {
            "AES", "CAMELLIA", "CHACHA20POLY1305", "XCHACHA20POLY1305", "AEGIS256", "DES"
    };
    private static final int[] SIZES = {0, 1, 15, 16, 17, 65535, 65536, 65537, 200003};
    private static final SecureRandom RNG = new SecureRandom();

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    private static byte[] enc(String c, byte[] d, String pw) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        StreamCrypto.encrypt(c, pw, new ByteArrayInputStream(d), o, null);
        return o.toByteArray();
    }

    private static byte[] dec(String c, byte[] d, String pw) throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        StreamCrypto.decrypt(c, pw, new ByteArrayInputStream(d), o, null);
        return o.toByteArray();
    }

    @Test
    public void roundTripAllCiphersAndSizes() throws Exception {
        for (String c : CIPHERS) {
            for (int n : SIZES) {
                byte[] data = random(n);
                assertArrayEquals(c + " size " + n, data, dec(c, enc(c, data, "secret-key"), "secret-key"));
            }
        }
    }

    @Test
    public void aegisMatchesLegacyOneShotFormat() throws Exception {
        for (int n : SIZES) {
            byte[] data = random(n);
            byte[] encrypted = enc("AEGIS256", data, "pw");
            byte[] salt = Arrays.copyOfRange(encrypted, 0, 16);
            byte[] nonce = Arrays.copyOfRange(encrypted, 16, 48);
            byte[] rest = Arrays.copyOfRange(encrypted, 48, encrypted.length);
            Aegis256 legacy = new Aegis256(StreamCrypto.deriveKey("pw", salt), nonce, 16);
            assertArrayEquals("size " + n, data, legacy.decrypt(rest, null));
            // y en sentido contrario: cifrado clásico -> descifrado por flujo
            byte[] nonce2 = random(32);
            byte[] key = StreamCrypto.deriveKey("pw", salt);
            byte[] old = new Aegis256(key, nonce2, 16).encrypt(data, null);
            byte[] file = new byte[16 + 32 + old.length];
            System.arraycopy(salt, 0, file, 0, 16);
            System.arraycopy(nonce2, 0, file, 16, 32);
            System.arraycopy(old, 0, file, 48, old.length);
            assertArrayEquals("size " + n, data, dec("AEGIS256", file, "pw"));
        }
    }

    @Test
    public void desMatchesLegacyEcbPkcs5() throws Exception {
        for (int n : new int[]{0, 1, 7, 8, 9, 100000}) {
            byte[] data = random(n);
            Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Arrays.copyOf("secret12".getBytes("UTF-8"), 8), "DES"));
            byte[] legacy = c.doFinal(data);
            assertArrayEquals(legacy, enc("DES", data, "secret12"));
            assertArrayEquals(data, dec("DES", legacy, "secret12"));
        }
    }

    @Test
    public void wrongKeyTamperedAndTruncatedAreRejected() throws Exception {
        for (String c : new String[]{"AES", "CAMELLIA", "CHACHA20POLY1305", "XCHACHA20POLY1305", "AEGIS256"}) {
            byte[] good = enc(c, random(70000), "right");
            expectFailure(c + " wrong key", () -> dec(c, good, "wrong"));

            byte[] tampered = good.clone();
            tampered[tampered.length / 2] ^= 1;
            expectFailure(c + " tampered", () -> dec(c, tampered, "right"));

            byte[] truncated = Arrays.copyOf(good, good.length - 1);
            expectFailure(c + " truncated", () -> dec(c, truncated, "right"));

            expectFailure(c + " too short", () -> dec(c, new byte[5], "right"));
        }
    }

    @Test
    public void encryptionIsRandomized() throws Exception {
        byte[] data = random(1000);
        assertEquals(false, Arrays.equals(enc("AES", data, "k"), enc("AES", data, "k")));
    }

    private interface Action {
        void run() throws Exception;
    }

    private static void expectFailure(String msg, Action a) {
        try {
            a.run();
        } catch (Exception expected) {
            return;
        }
        fail(msg + ": should have failed");
    }
}
