package com.zim.nfctag.core;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class Bytes {
  private Bytes() {}

  public static byte[] hex(String s) {
    if (s == null || (s.length() & 1) != 0)
      throw new IllegalArgumentException("Invalid hex length");
    byte[] out = new byte[s.length() / 2];
    for (int i = 0; i < out.length; i++) {
      int a = Character.digit(s.charAt(i * 2), 16), b = Character.digit(s.charAt(i * 2 + 1), 16);
      if (a < 0 || b < 0) throw new IllegalArgumentException("Use hexadecimal digits only");
      out[i] = (byte) ((a << 4) | b);
    }
    return out;
  }

  public static String hex(byte[] b) {
    char[] out = new char[b.length * 2];
    char[] alphabet = "0123456789ABCDEF".toCharArray();
    for (int i = 0; i < b.length; i++) {
      out[i * 2] = alphabet[(b[i] & 255) >>> 4];
      out[i * 2 + 1] = alphabet[b[i] & 15];
    }
    return new String(out);
  }

  public static byte[] ascii(String s) {
    return s.getBytes(StandardCharsets.US_ASCII);
  }

  public static byte[] join(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] p : parts) out.write(p, 0, p.length);
    return out.toByteArray();
  }

  public static byte[] le(int n, int size) {
    byte[] out = new byte[size];
    for (int i = 0; i < size; i++) out[i] = (byte) (n >>> (8 * i));
    return out;
  }

  public static byte[] xor(byte[] a, byte[] b) {
    if (a.length != b.length) throw new IllegalArgumentException("Length mismatch");
    byte[] out = new byte[a.length];
    for (int i = 0; i < out.length; i++) out[i] = (byte) (a[i] ^ b[i]);
    return out;
  }

  public static byte[] slice(byte[] a, int start, int end) {
    if (start < 0 || end > a.length || end < start)
      throw new IllegalArgumentException("Truncated data");
    return Arrays.copyOfRange(a, start, end);
  }

  public static byte[] rotateLeft(byte[] a) {
    return join(slice(a, 1, a.length), slice(a, 0, 1));
  }
}
