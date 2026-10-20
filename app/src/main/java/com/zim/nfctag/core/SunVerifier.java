package com.zim.nfctag.core;

import java.net.URI;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/** Offline AES verification matching the Go backend's separated TagTamper layout. */
public final class SunVerifier {
  public static final class Result {
    public final String uid, status;
    public final int counter;
    public final byte[] file;

    Result(byte[] uid, int counter, byte[] file) {
      this.uid = Bytes.hex(uid);
      this.counter = counter;
      this.file = file;
      String code = new String(Bytes.slice(file, 0, 2), java.nio.charset.StandardCharsets.US_ASCII);
      switch (code) {
        case "CC":
          status = "Secure — loop closed";
          break;
        case "OC":
          status = "Tampered — loop closed again";
          break;
        case "OO":
          status = "Tampered — loop open";
          break;
        case "II":
          status = "Tamper detection not initialized";
          break;
        default:
          status = "Unknown tamper state: " + code;
      }
    }
  }

  public static Result verify(String url, byte[] master, String mode) {
    URI u = URI.create(url);
    Map<String, String> query = new HashMap<>();
    if (u.getRawQuery() == null) throw new IllegalArgumentException("No dynamic data on tag");
    for (String part : u.getRawQuery().split("&")) {
      String[] kv = part.split("=", -1);
      if (kv.length != 2 || query.put(kv[0], kv[1]) != null)
        throw new IllegalArgumentException("Invalid tag URL parameters");
    }
    if (query.size() != 3) throw new IllegalArgumentException("Unexpected tag URL parameters");
    byte[] picc = Bytes.hex(query.get("picc_data")),
        encryptedFile = Bytes.hex(query.get("enc")),
        received = Bytes.hex(query.get("cmac"));
    if (picc.length != 16 || encryptedFile.length != 16 || received.length != 8)
      throw new IllegalArgumentException("Unsupported SDM layout");
    // Key 1 is independent of UID. A placeholder UID is safe for this slot only.
    byte[] pt = Crypto.aes(Crypto.derive(master, new byte[7], 1, mode), new byte[16], picc, false);
    if (pt[0] != (byte) 0xc7)
      throw new IllegalArgumentException("Wrong key or unsupported PICC header");
    byte[] uid = Bytes.slice(pt, 1, 8),
        data = Bytes.slice(pt, 1, 11),
        key = Crypto.derive(master, uid, 2, mode);
    byte[] macKey = Crypto.cmac(key, Bytes.join(Bytes.hex("3CC300010080"), data));
    byte[] expected =
        Crypto.shortMac(
            Crypto.cmac(macKey, Bytes.ascii(query.get("enc").toUpperCase(Locale.ROOT) + "&cmac=")));
    if (!MessageDigest.isEqual(expected, received))
      throw new IllegalArgumentException("Tag signature is invalid");
    byte[] encKey = Crypto.cmac(key, Bytes.join(Bytes.hex("C33C00010080"), data));
    byte[] iv =
        Crypto.aes(encKey, new byte[16], Bytes.join(Bytes.slice(pt, 8, 11), new byte[13]), true);
    byte[] file = Crypto.aes(encKey, iv, encryptedFile, false);
    int counter = (pt[8] & 255) | ((pt[9] & 255) << 8) | ((pt[10] & 255) << 16);
    return new Result(uid, counter, file);
  }
}
