package com.aakash.qsec.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class EncodingUtilTest {

    @Test
    void base64_roundTrip() {
        byte[] original = EncodingUtil.utf8("Hello World!");
        String encoded = EncodingUtil.base64Encode(original);
        byte[] decoded = EncodingUtil.base64Decode(encoded);
        assertArrayEquals(original, decoded);
    }

    @Test
    void base64_knownVector() {
        // "abc" in standard Base64 is a stable, known value
        assertEquals("YWJj", EncodingUtil.base64Encode(EncodingUtil.utf8("abc")));
    }

    @Test
    void base64Url_hasNoPaddingOrUnsafeChars() {
        // Bytes that would produce '+' '/' '=' in standard Base64
        byte[] tricky = EncodingUtil.fromHex("fbffbf");
        String url = EncodingUtil.base64UrlEncode(tricky);
        // URL-safe alphabet must not contain +, /, or =
        assert !url.contains("+");
        assert !url.contains("/");
        assert !url.contains("=");
    }

    @Test
    void hex_roundTrip() {
        byte[] original = EncodingUtil.utf8("bytes");
        String h = EncodingUtil.hex(original);
        assertArrayEquals(original, EncodingUtil.fromHex(h));
    }

}
