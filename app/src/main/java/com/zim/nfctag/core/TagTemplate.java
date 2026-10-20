package com.zim.nfctag.core;

import java.net.URI;

/** Exact Type 4 NDEF file, including NLEN; offsets refer to file byte zero. */
public final class TagTemplate {
  public final String endpoint, url;
  public final byte[] file, settings;
  public final int piccOffset, encOffset, macOffset;

  public TagTemplate(String endpoint) {
    URI uri;
    try {
      uri = URI.create(endpoint);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Enter a valid HTTPS URL");
    }
    if (!"https".equals(uri.getScheme())
        || uri.getHost() == null
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null
        || uri.getUserInfo() != null
        || !(uri.getPath().equals("/tagtt") || uri.getPath().equals("/api/tagtt")))
      throw new IllegalArgumentException(
          "Use an HTTPS URL ending in /tagtt or /api/tagtt, without a query");
    for (int i = 0; i < endpoint.length(); i++)
      if (endpoint.charAt(i) < 33 || endpoint.charAt(i) > 126)
        throw new IllegalArgumentException("Use an ASCII URL (percent-encode other characters)");
    this.endpoint = endpoint;
    String body = endpoint.substring(8) + "?picc_data=";
    piccOffset = 7 + body.length();
    body += zeros(32) + "&enc=";
    encOffset = 7 + body.length();
    // First 16 bytes are the plaintext placeholder; SDM expands it into 32 hex characters.
    body += "II" + zeros(30) + "&cmac=";
    macOffset = 7 + body.length();
    body += zeros(16);
    url = "https://" + body;
    byte[] record =
        Bytes.join(
            new byte[] {(byte) 0xd1, 1, (byte) (body.length() + 1), 'U', 4}, Bytes.ascii(body));
    file = Bytes.join(new byte[] {(byte) (record.length >>> 8), (byte) record.length}, record);
    if (file.length > 256)
      throw new IllegalArgumentException("URL is too long for the 256-byte NDEF file");
    // Plain file reads; writes/RW/settings require key 0. UID+ctr+encrypted file+TT+ASCII.
    // SDMAccessRights: counter retrieval key 0, meta key 1, file key 2 (LSB first: F0 12).
    settings =
        Bytes.join(
            Bytes.hex("4000E0D9F012"),
            Bytes.le(piccOffset, 3),
            Bytes.le(encOffset, 3),
            Bytes.le(encOffset, 3),
            Bytes.le(encOffset, 3),
            Bytes.le(32, 3),
            Bytes.le(macOffset, 3));
  }

  private static String zeros(int n) {
    char[] s = new char[n];
    java.util.Arrays.fill(s, '0');
    return new String(s);
  }

  public static String decodeFile(byte[] file) {
    if (file.length < 7 || file[2] != (byte) 0xd1 || file[3] != 1 || file[5] != 'U' || file[6] != 4)
      throw new IllegalArgumentException("Unexpected NDEF layout");
    int length = (file[0] & 255) * 256 + (file[1] & 255);
    if (length + 2 != file.length || (file[4] & 255) + 4 != length)
      throw new IllegalArgumentException("Invalid NDEF length");
    return "https://"
        + new String(Bytes.slice(file, 7, file.length), java.nio.charset.StandardCharsets.US_ASCII);
  }
}
