package com.aakash.qsec.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class HashUtilTest {

    @Test
    void sha256OfEmptyString_matchesKnownVector() {
        // Published SHA-256 of zero-length input (a standard test vector)
        String expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        byte[] hash = HashUtil.sha256(new byte[0]);
        String actual = HexFormat.of().formatHex(hash);

        assertEquals(expected, actual);
    }

    @Test
    void sha256OfAbc_matchesKnownVector() {
        String expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        byte[] hash = HashUtil.sha256("abc");
        String actual = HexFormat.of().formatHex(hash);

        assertEquals(expected, actual);
    }
    
}
