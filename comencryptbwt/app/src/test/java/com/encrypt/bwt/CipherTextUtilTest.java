package com.encrypt.bwt;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.AEADBadTagException;

public class CipherTextUtilTest {

    private static byte[] data(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    @Test
    public void decodesPlainBase64OfAnySize() {
        for (int n : new int[]{1, 2, 3, 4, 100, 100000, 3_000_000}) {
            byte[] d = data(n);
            assertArrayEquals(d, CipherTextUtil.decode(Base64.getEncoder().encodeToString(d)));
        }
    }

    @Test
    public void toleratesLineBreaksSpacesQuotesAndLostPadding() {
        byte[] d = data(50_000);
        String b64 = Base64.getEncoder().encodeToString(d);
        String wrapped = Base64.getMimeEncoder(76, "\r\n".getBytes()).encodeToString(d);
        assertArrayEquals(d, CipherTextUtil.decode(wrapped));
        assertArrayEquals(d, CipherTextUtil.decode("  \"" + b64 + "\"\n"));
        assertArrayEquals(d, CipherTextUtil.decode("`" + b64 + "`"));
        assertArrayEquals(d, CipherTextUtil.decode(b64.replaceAll("=+$", "")));
        assertArrayEquals(d, CipherTextUtil.decode(b64.replace('+', '-').replace('/', '_')));
        assertArrayEquals(d, CipherTextUtil.decode("﻿" + b64.substring(0, 10) + "​" + b64.substring(10)));
    }

    @Test
    public void reportsTruncatedAndInvalidText() {
        String b64 = Base64.getEncoder().encodeToString(data(1000)).replaceAll("=+$", "");
        try {
            CipherTextUtil.decode(b64.substring(0, 41)); // 41 символ: хвост обрезан
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().startsWith("Encrypted text"));
        }
        try {
            CipherTextUtil.decode("abcd$efgh");
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("'$'"));
        }
        try {
            CipherTextUtil.decode("   ");
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("Encrypted text"));
        }
    }

    @Test
    public void explainsAuthenticationFailures() {
        String msg = CipherTextUtil.explainDecryptFailure(new AEADBadTagException("x"), "abc");
        assertTrue(msg, msg.contains("wrong key"));
    }
}
