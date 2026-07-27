package com.aakash.qsec.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class HmacUtilTest {

    @Test
    void hmacSha256_rfc4231_testCase1() {
        // RFC 4231, Test Case 1:
        // key = 0x0b repeated 20 times, data = "Hi There"
        byte[] key = new byte[20];
        java.util.Arrays.fill(key, (byte) 0x0b);
        byte[] data = EncodingUtil.utf8("Hi There");

        String expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        byte[] mac = HmacUtil.hmacSha256(key, data);
        assertEquals(expected, EncodingUtil.hex(mac));
    }
}
