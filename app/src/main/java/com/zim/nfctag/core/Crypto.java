package com.zim.nfctag.core;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.zip.CRC32;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Crypto {
  private Crypto() {}

  public static byte[] aes(byte[] key, byte[] iv, byte[] data, boolean encrypt) {
    try {
      Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
      c.init(
          encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
          new SecretKeySpec(key, "AES"),
          new IvParameterSpec(iv));
      return c.doFinal(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("AES unavailable", e);
    }
  }

  public static byte[] pad(byte[] x) {
    byte[] out = Arrays.copyOf(x, (x.length / 16 + 1) * 16);
    out[x.length] = (byte) 128;
    return out;
  }

  public static byte[] unpad(byte[] x) {
    int i = x.length - 1;
    while (i >= 0 && x[i] == 0) i--;
    if (i < 0 || x[i] != (byte) 128)
      throw new IllegalArgumentException("Invalid encrypted response padding");
    return Arrays.copyOf(x, i);
  }

  private static byte[] twice(byte[] x) {
    byte[] out = new byte[16];
    for (int i = 0; i < 16; i++) {
      out[i] = (byte) ((x[i] & 255) << 1);
      if (i < 15) out[i] |= (byte) ((x[i + 1] & 255) >>> 7);
    }
    if ((x[0] & 128) != 0) out[15] ^= (byte) 0x87;
    return out;
  }

  public static byte[] cmac(byte[] key, byte[] data) {
    byte[] k1 = twice(aes(key, new byte[16], new byte[16], true)), k2 = twice(k1), y = new byte[16];
    int offset = 0;
    while (data.length - offset > 16) {
      y = aes(key, new byte[16], Bytes.xor(y, Bytes.slice(data, offset, offset + 16)), true);
      offset += 16;
    }
    int size = data.length - offset;
    byte[] last = new byte[16];
    System.arraycopy(data, offset, last, 0, size);
    if (size == 16) last = Bytes.xor(last, k1);
    else {
      last[size] = (byte) 128;
      last = Bytes.xor(last, k2);
    }
    return aes(key, new byte[16], Bytes.xor(y, last), true);
  }

  public static byte[] shortMac(byte[] mac) {
    byte[] out = new byte[8];
    for (int i = 0; i < 8; i++) out[i] = mac[i * 2 + 1];
    return out;
  }

  public static byte[] hmac(String algorithm, byte[] key, byte[] data) {
    try {
      Mac m = Mac.getInstance(algorithm);
      m.init(new SecretKeySpec(key, algorithm));
      return m.doFinal(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HMAC unavailable", e);
    }
  }

  public static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  public static byte[] jamCRC(byte[] data) {
    CRC32 crc = new CRC32();
    crc.update(data);
    return Bytes.le((int) (crc.getValue() ^ 0xffffffffL), 4);
  }

  public static byte[] sessionKey(byte[] key, byte[] a, byte[] b, boolean encryption) {
    byte[] prefix = Bytes.hex(encryption ? "A55A00010080" : "5AA500010080");
    return cmac(
        key,
        Bytes.join(
            prefix,
            Bytes.slice(a, 0, 2),
            Bytes.xor(Bytes.slice(a, 2, 8), Bytes.slice(b, 0, 6)),
            Bytes.slice(b, 6, 16),
            Bytes.slice(a, 8, 16)));
  }

  public static byte[] derive(byte[] master, byte[] uid, int key, String mode) {
    if (master.length != 16 && master.length != 32)
      throw new IllegalArgumentException("Master key must be 16 or 32 bytes");
    if (key < 0 || key > 4 || uid.length != 7)
      throw new IllegalArgumentException("Invalid tag or key slot");
    if (!mode.equals("legacy") && !mode.equals("standard"))
      throw new IllegalArgumentException("Unknown derivation mode");
    if (Arrays.equals(master, new byte[16])) return new byte[16];
    if (mode.equals("legacy")) {
      byte[] salt = key == 1 ? Bytes.ascii("key_no_uid") : Bytes.join(Bytes.ascii("key"), uid);
      byte[]
          u =
              hmac(
                  "HmacSHA512",
                  master,
                  Bytes.join(salt, new byte[] {(byte) key}, new byte[] {0, 0, 0, 1})),
          result = u.clone();
      for (int i = 1; i < 5000; i++) {
        u = hmac("HmacSHA512", master, u);
        for (int j = 0; j < result.length; j++) result[j] ^= u[j];
      }
      return Arrays.copyOf(result, 16);
    }
    if (key == 1) return Arrays.copyOf(hmac("HmacSHA256", master, Bytes.ascii("PICCDataKey")), 16);
    byte[] slot =
        Arrays.copyOf(
            hmac(
                "HmacSHA256",
                master,
                Bytes.join(Bytes.ascii("SlotMasterKey"), new byte[] {(byte) key})),
            16);
    byte[] div =
        Arrays.copyOf(
            hmac("HmacSHA256", hmac("HmacSHA256", master, Bytes.ascii("DivBaseKey")), uid), 16);
    return cmac(slot, Bytes.join(new byte[] {1}, div));
  }
}
