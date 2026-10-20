package com.zim.nfctag.core;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/** AES EV2First and secure messaging. A session is invalidated after any failed command. */
public final class TagSession {
  public static final class StatusException extends IOException {
    public final int status;

    StatusException(String operation, int status) {
      super(String.format(java.util.Locale.ROOT, "%s: tag returned %04X", operation, status));
      this.status = status;
    }
  }

  public interface Transport {
    byte[] transceive(byte[] apdu) throws IOException;
  }

  public interface RandomSource {
    void fill(byte[] bytes);
  }

  private final Transport transport;
  private final RandomSource random;
  private byte[] encKey, macKey, ti;
  private int counter, authenticatedKey = -1;

  public TagSession(Transport transport) {
    this(transport, new SecureRandom()::nextBytes);
  }

  public TagSession(Transport transport, RandomSource random) {
    this.transport = transport;
    this.random = random;
  }

  private void clear() {
    // Clear our mutable session material before dropping references. This is best-effort;
    // JVM/cipher internals may retain their own copies until garbage collection.
    if (encKey != null) Arrays.fill(encKey, (byte) 0);
    if (macKey != null) Arrays.fill(macKey, (byte) 0);
    if (ti != null) Arrays.fill(ti, (byte) 0);
    encKey = null;
    macKey = null;
    ti = null;
    counter = 0;
    authenticatedKey = -1;
  }

  private static final class Response {
    final byte[] data;
    final int status;
    final String operation;

    Response(byte[] raw) throws IOException {
      this(raw, "NFC command");
    }

    Response(byte[] raw, String operation) throws IOException {
      this.operation = operation;
      if (raw == null || raw.length < 2) throw new IOException("Truncated NFC response");
      data = Arrays.copyOf(raw, raw.length - 2);
      status = (raw[raw.length - 2] & 255) * 256 + (raw[raw.length - 1] & 255);
    }

    byte[] expect(int code) throws IOException {
      if (status != code) throw new StatusException(operation, status);
      return data;
    }
  }

  public void selectApplication() throws IOException {
    // ISOSelectFile by the NDEF application's registered DF name, not a relative file ID.
    // NXP NT4H2421Tx section 11.10.1: P1=04, P2=0C, DF name D2760000850101.
    clear();
    new Response(
            transport.transceive(Bytes.hex("00A4040C07D276000085010100")),
            "Select NTAG application")
        .expect(0x9000);
  }

  private Response command(int cmd, byte[] data) throws IOException {
    if (data.length > 255) throw new IOException("APDU is too large");
    byte[] apdu =
        data.length == 0
            ? new byte[] {(byte) 0x90, (byte) cmd, 0, 0, 0}
            : Bytes.join(
                new byte[] {(byte) 0x90, (byte) cmd, 0, 0, (byte) data.length},
                data,
                new byte[] {0});
    return new Response(
        transport.transceive(apdu),
        String.format(java.util.Locale.ROOT, "Native command %02X", cmd));
  }

  public byte[] version() throws IOException {
    if (authenticatedKey >= 0)
      throw new IOException("GetVersion requires a fresh session in this app");
    byte[] hw = command(0x60, new byte[0]).expect(0x91af),
        sw = command(0xaf, new byte[0]).expect(0x91af),
        production = command(0xaf, new byte[0]).expect(0x9100);
    if (hw.length != 7 || sw.length != 7 || production.length != 14)
      throw new IOException("Unexpected GetVersion data");
    if (hw[0] != 4
        || hw[1] != 4
        || (hw[2] & 15) != 8
        || hw[3] != 0x30
        || hw[5] != 0x11
        || hw[6] != 5
        || sw[0] != 4
        || sw[1] != 4
        || sw[2] != 2
        || sw[3] != 1
        || sw[4] != 2) throw new IOException("This app supports NTAG 424 DNA TagTamper only");
    return Bytes.slice(production, 0, 7);
  }

  public void authenticate(int number, byte[] key) throws IOException {
    clear();
    if (number < 0 || number > 4 || key.length != 16)
      throw new IOException("Invalid authentication key");
    try {
      byte[] encryptedB = command(0x71, new byte[] {(byte) number, 0}).expect(0x91af);
      if (encryptedB.length != 16) throw new IOException("Tag is not in supported AES mode");
      byte[] b = Crypto.aes(key, new byte[16], encryptedB, false), a = new byte[16];
      random.fill(a);
      byte[] challenge = Crypto.aes(key, new byte[16], Bytes.join(a, Bytes.rotateLeft(b)), true);
      byte[] reply = command(0xaf, challenge).expect(0x9100);
      if (reply.length != 32) throw new IOException("Invalid authentication response");
      byte[] pt = Crypto.aes(key, new byte[16], reply, false);
      if (!MessageDigest.isEqual(Bytes.slice(pt, 4, 20), Bytes.rotateLeft(a)))
        throw new IOException("Tag authentication proof failed");
      if (!Arrays.equals(Bytes.slice(pt, 26, 32), new byte[6]) || (pt[21] & 2) != 0)
        throw new IOException("Unsupported tag authentication capabilities");
      ti = Bytes.slice(pt, 0, 4);
      encKey = Crypto.sessionKey(key, a, b, true);
      macKey = Crypto.sessionKey(key, a, b, false);
      counter = 0;
      authenticatedKey = number;
    } catch (IOException | RuntimeException e) {
      clear();
      throw e;
    }
  }

  private byte[] iv(boolean response, int ctr) {
    return Crypto.aes(
        encKey,
        new byte[16],
        Bytes.join(Bytes.hex(response ? "5AA5" : "A55A"), ti, Bytes.le(ctr, 2), new byte[8]),
        true);
  }

  private byte[] secure(
      int cmd,
      byte[] header,
      byte[] data,
      boolean encrypted,
      boolean encryptedResponse,
      boolean dropsSession)
      throws IOException {
    if (authenticatedKey < 0 || counter >= 65535)
      throw new IOException("An authenticated session is required");
    try {
      byte[] payload =
          encrypted && data.length > 0
              ? Crypto.aes(encKey, iv(false, counter), Crypto.pad(data), true)
              : data;
      byte[] mac =
          Crypto.shortMac(
              Crypto.cmac(
                  macKey,
                  Bytes.join(new byte[] {(byte) cmd}, Bytes.le(counter, 2), ti, header, payload)));
      byte[] response = command(cmd, Bytes.join(header, payload, mac)).expect(0x9100);
      counter++;
      if (dropsSession) { // Changing the active key terminates authentication; response has no MAC.
        if (response.length != 0) throw new IOException("Unexpected ChangeKey response");
        clear();
        return new byte[0];
      }
      if (response.length < 8) throw new IOException("Missing secure response MAC");
      byte[] body = Bytes.slice(response, 0, response.length - 8),
          actual = Bytes.slice(response, response.length - 8, response.length);
      byte[] expected =
          Crypto.shortMac(
              Crypto.cmac(macKey, Bytes.join(new byte[] {0}, Bytes.le(counter, 2), ti, body)));
      if (!MessageDigest.isEqual(actual, expected))
        throw new IOException("Secure response MAC is invalid");
      if (encryptedResponse && body.length > 0) {
        if (body.length % 16 != 0) throw new IOException("Invalid encrypted response length");
        body = Crypto.unpad(Crypto.aes(encKey, iv(true, counter), body, false));
      }
      return body;
    } catch (IOException | RuntimeException e) {
      clear();
      throw e;
    }
  }

  public byte[] uid() throws IOException {
    byte[] uid = secure(0x51, new byte[0], new byte[0], true, true, false);
    if (uid.length != 7) throw new IOException("Invalid UID length");
    return uid;
  }

  public byte[] fileSettings() throws IOException {
    return fileSettings(2);
  }

  public byte[] fileSettings(int file) throws IOException {
    return secure(0xf5, new byte[] {(byte) file}, new byte[0], false, false, false);
  }

  public void changeSettings(byte[] data) throws IOException {
    changeSettings(2, data);
  }

  public void changeSettings(int file, byte[] data) throws IOException {
    requireManagement();
    secure(0x5f, new byte[] {(byte) file}, data, true, false, false);
  }

  public void enableTamper() throws IOException {
    requireManagement();
    secure(0x5c, new byte[] {7}, new byte[] {1, 0}, true, false, false);
  }

  public void changeKey(int number, byte[] oldKey, byte[] newKey) throws IOException {
    requireManagement();
    if (number < 0 || number > 4 || oldKey.length != 16 || newKey.length != 16)
      throw new IOException("Invalid key change");
    byte[] data =
        number == 0
            ? Bytes.join(newKey, new byte[] {1})
            : Bytes.join(Bytes.xor(newKey, oldKey), new byte[] {1}, Crypto.jamCRC(newKey));
    secure(0xc4, new byte[] {(byte) number}, data, true, false, number == 0);
  }

  private void requireManagement() throws IOException {
    if (authenticatedKey != 0) throw new IOException("Management key 0 is required");
  }

  public void writeFile(int offset, byte[] data) throws IOException {
    requireManagement();
    if (offset < 0 || offset > 256 || data.length > 256 - offset)
      throw new IOException("NDEF write exceeds file bounds");
    try {
      // Each WriteData fits within one native frame; file 02 is configured CommMode.Plain.
      for (int i = 0; i < data.length; i += 48) {
        if (counter >= 65535) throw new IOException("Session command counter exhausted");
        byte[] chunk = Bytes.slice(data, i, Math.min(data.length, i + 48));
        command(
                0x8d,
                Bytes.join(
                    new byte[] {2}, Bytes.le(offset + i, 3), Bytes.le(chunk.length, 3), chunk))
            .expect(0x9100);
        counter++;
      }
    } catch (IOException | RuntimeException e) {
      clear();
      throw e;
    }
  }

  public byte[] readStatic(int offset, int length) throws IOException {
    if (authenticatedKey < 0) throw new IOException("Authentication required for static readback");
    if (offset < 0 || offset > 256 || length < 0 || length > 256 - offset)
      throw new IOException("NDEF read exceeds file bounds");
    try {
      byte[] result = new byte[0];
      for (int i = 0; i < length; i += 48) {
        if (counter >= 65535) throw new IOException("Session command counter exhausted");
        int count = Math.min(48, length - i);
        byte[] part =
            command(0xad, Bytes.join(new byte[] {2}, Bytes.le(offset + i, 3), Bytes.le(count, 3)))
                .expect(0x9100);
        counter++;
        if (part.length != count) throw new IOException("Truncated file read");
        result = Bytes.join(result, part);
      }
      return result;
    } catch (IOException | RuntimeException e) {
      clear();
      throw e;
    }
  }

  public String readDynamicURL() throws IOException {
    selectApplication();
    new Response(transport.transceive(Bytes.hex("00A4020C02E10400")), "Select NDEF file")
        .expect(0x9000);
    byte[] nlen = new Response(transport.transceive(Bytes.hex("00B0000002"))).expect(0x9000);
    if (nlen.length != 2) throw new IOException("Invalid NDEF length");
    int length = (nlen[0] & 255) * 256 + (nlen[1] & 255);
    if (length < 5 || length > 254) throw new IOException("NDEF file is empty or unsupported");
    byte[] file = nlen;
    // Only consecutive ISOReadBinary calls: mirrored data remains stable between chunks.
    for (int offset = 2; offset < length + 2; offset += 48) {
      int count = Math.min(48, length + 2 - offset);
      byte[] data =
          new Response(
                  transport.transceive(
                      new byte[] {
                        0, (byte) 0xb0, (byte) (offset >>> 8), (byte) offset, (byte) count
                      }))
              .expect(0x9000);
      if (data.length != count) throw new IOException("Truncated NDEF read");
      file = Bytes.join(file, data);
    }
    return TagTemplate.decodeFile(file);
  }
}
