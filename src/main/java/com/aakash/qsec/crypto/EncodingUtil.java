package com.aakash.qsec.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

public final class EncodingUtil {
    
    private EncodingUtil() {}

    // --Base64 (standard)
    public static String base64Encode(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    public static byte[] base64Decode(String input) {
        return Base64.getDecoder().decode(input);
    }

    // --Base64URL (URL-safe, no padding)
    public static String base64UrlEncode(byte[] input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
    }

    public static byte[] base64UrlDecode(String input) {
        return Base64.getUrlDecoder().decode(input);
    }

    // --Hex
    public static String hex(byte[] input) {
        return HexFormat.of().formatHex(input);
    }

    public static byte[] fromHex(String input) {
        return HexFormat.of().parseHex(input);
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

}
