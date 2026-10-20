package com.zim.nfctag.core;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;
import org.junit.Test;

public class ProvisionerTest {
  /**
   * Simulates card state and lost responses to test ordering and recovery, not physical RF
   * behavior.
   */
  static final class Card implements TagSession.Transport {
    byte[][] keys = {new byte[16], new byte[16], new byte[16], new byte[16], new byte[16]};
    byte[] uid = Bytes.hex("04112233445566"),
        file = new byte[256],
        settings = Bytes.hex("00E0EE"),
        b = Bytes.hex("B9E2FC789B64BF237CCCAA20EC7E6E48"),
        ti = Bytes.hex("11223344"),
        enc,
        mac;
    int auth = -1, challengeKey = -1, frame = 0, ctr = 0, writes = 0, loseAfterKey = -1;
    boolean enabled = false;
    List<Integer> changedKeys = new ArrayList<>();
    byte[] ccSettings = Bytes.hex("0000E0"), privateSettings = Bytes.hex("030023");
    int loseAfterFile = -1;

    byte[] fileOptions(int file) {
      return file == 1 ? ccSettings : file == 2 ? settings : privateSettings;
    }

    byte[] response(byte[] data, int status) {
      return Bytes.join(data, new byte[] {(byte) (status >>> 8), (byte) status});
    }

    byte[] settingsResponse() {
      return Bytes.join(
          new byte[] {0},
          Bytes.slice(settings, 0, 3),
          Bytes.le(256, 3),
          Bytes.slice(settings, 3, settings.length));
    }

    @Override
    public byte[] transceive(byte[] apdu) throws IOException {
      if (apdu[0] == 0) {
        if (!Arrays.equals(apdu, Bytes.hex("00A4040C07D276000085010100")))
          return response(new byte[0], 0x6a82);
        auth = -1;
        return response(new byte[0], 0x9000);
      }
      int cmd = apdu[1] & 255;
      byte[] data = apdu.length == 5 ? new byte[0] : Bytes.slice(apdu, 5, apdu.length - 1);
      if (cmd == 0x60) {
        frame = 1;
        return response(Bytes.hex("04040830001105"), 0x91af);
      }
      if (cmd == 0xaf && frame > 0) {
        if (frame++ == 1) return response(Bytes.hex("04040201021105"), 0x91af);
        frame = 0;
        return response(Bytes.join(uid, new byte[7]), 0x9100);
      }
      if (cmd == 0x71) {
        auth = -1;
        challengeKey = data[0] & 255;
        return response(Crypto.aes(keys[challengeKey], new byte[16], b, true), 0x91af);
      }
      if (cmd == 0xaf && challengeKey >= 0) {
        byte[] plain = Crypto.aes(keys[challengeKey], new byte[16], data, false),
            a = Bytes.slice(plain, 0, 16);
        if (!Arrays.equals(Bytes.slice(plain, 16, 32), Bytes.rotateLeft(b))) {
          challengeKey = -1;
          return response(new byte[0], 0x91ae);
        }
        auth = challengeKey;
        challengeKey = -1;
        ctr = 0;
        enc = Crypto.sessionKey(keys[auth], a, b, true);
        mac = Crypto.sessionKey(keys[auth], a, b, false);
        return response(
            Crypto.aes(
                keys[auth], new byte[16], Bytes.join(ti, Bytes.rotateLeft(a), new byte[12]), true),
            0x9100);
      }
      if (auth < 0) return response(new byte[0], 0x91ae);
      if (cmd == 0x8d || cmd == 0xad) {
        if (cmd == 0x8d && (settings[2] & 15) == 15 && ((settings[1] & 255) >>> 4) == 15)
          return response(new byte[0], 0x919d);
        assertEquals(0, settings[0] & 3);
        int offset = number(data, 1), length = number(data, 4);
        ctr++;
        if (cmd == 0x8d) {
          assertEquals(0, auth);
          writes++;
          System.arraycopy(data, 7, file, offset, length);
          return response(new byte[0], 0x9100);
        }
        return response(Bytes.slice(file, offset, offset + length), 0x9100);
      }
      int head = (cmd == 0x51 ? 0 : 1);
      byte[] header = Bytes.slice(data, 0, head),
          payload = Bytes.slice(data, head, data.length - 8),
          received = Bytes.slice(data, data.length - 8, data.length);
      assertArrayEquals(
          Crypto.shortMac(
              Crypto.cmac(
                  mac, Bytes.join(new byte[] {(byte) cmd}, Bytes.le(ctr, 2), ti, header, payload))),
          received);
      boolean full = cmd == 0x5f || cmd == 0x5c || cmd == 0xc4;
      if (full) {
        assertEquals(0, auth);
        byte[] iv =
            Crypto.aes(
                enc,
                new byte[16],
                Bytes.join(Bytes.hex("A55A"), ti, Bytes.le(ctr, 2), new byte[8]),
                true);
        payload = Crypto.unpad(Crypto.aes(enc, iv, payload, false));
        writes++;
      }
      ctr++;
      byte[] reply = new byte[0];
      if (cmd == 0x51) {
        byte[] iv =
            Crypto.aes(
                enc,
                new byte[16],
                Bytes.join(Bytes.hex("5AA5"), ti, Bytes.le(ctr, 2), new byte[8]),
                true);
        reply = Crypto.aes(enc, iv, Crypto.pad(uid), true);
      } else if (cmd == 0xf5) {
        byte[] options = fileOptions(header[0]);
        reply =
            Bytes.join(
                new byte[] {0},
                Bytes.slice(options, 0, 3),
                Bytes.le(256, 3),
                Bytes.slice(options, 3, options.length));
      } else if (cmd == 0x5f) {
        int file = header[0];
        if ((fileOptions(file)[1] & 15) == 15) return response(new byte[0], 0x919d);
        if (file == 1) ccSettings = payload;
        else if (file == 2) settings = payload;
        else privateSettings = payload;
        if (loseAfterFile == file) {
          loseAfterFile = -1;
          throw new IOException("RF lost after locking file");
        }
      } else if (cmd == 0x5c) {
        assertArrayEquals(new byte[] {7}, header);
        assertArrayEquals(new byte[] {1, 0}, payload);
        enabled = true;
      } else if (cmd == 0xc4) {
        int key = header[0] & 255;
        byte[] next =
            key == 0
                ? Bytes.slice(payload, 0, 16)
                : Bytes.xor(keys[key], Bytes.slice(payload, 0, 16));
        assertEquals(1, payload[16]);
        if (key != 0) assertArrayEquals(Crypto.jamCRC(next), Bytes.slice(payload, 17, 21));
        keys[key] = next;
        changedKeys.add(key);
        if (loseAfterKey == key) {
          loseAfterKey = -1;
          throw new IOException("RF lost after successful key change");
        }
        if (key == 0) {
          auth = -1;
          return response(new byte[0], 0x9100);
        }
      } else throw new IOException("Unexpected command " + cmd);
      return response(
          Bytes.join(
              reply,
              Crypto.shortMac(
                  Crypto.cmac(mac, Bytes.join(new byte[] {0}, Bytes.le(ctr, 2), ti, reply)))),
          0x9100);
    }

    int number(byte[] x, int i) {
      return (x[i] & 255) | ((x[i + 1] & 255) << 8) | ((x[i + 2] & 255) << 16);
    }
  }

  static final class Journal implements Provisioner.Observer, Provisioner.Recovery {
    String uid, stage;
    boolean reject = false;

    public void progress(String s) {}

    public void checkpoint(String uid, String stage) throws IOException {
      if (reject) throw new IOException("journal unavailable");
      this.uid = uid;
      this.stage = stage;
    }

    public boolean permits(String uid) {
      return uid.equals(this.uid);
    }
  }

  private final byte[] master = Bytes.hex("C9EB67DF090AFF47C3B19A2516680B9D");
  private final TagTemplate template = new TagTemplate("https://example.com/tagtt");

  @Test
  public void completeProvisioningAndKeyZeroLast() throws Exception {
    Card c = new Card();
    Journal j = new Journal();
    assertEquals(
        "04112233445566",
        Provisioner.write(new TagSession(c), template, master, "legacy", false, j, j));
    assertArrayEquals(template.file, Bytes.slice(c.file, 0, template.file.length));
    assertArrayEquals(template.settings, c.settings);
    assertTrue(c.enabled);
    assertEquals(Arrays.asList(1, 2, 3, 4, 0), c.changedKeys);
    assertEquals("Complete", j.stage);
    for (int i = 0; i < 5; i++)
      assertArrayEquals(Crypto.derive(master, c.uid, i, "legacy"), c.keys[i]);
  }

  @Test
  public void resumesAmbiguousKeyChange() throws Exception {
    for (int interrupted : new int[] {1, 2, 3, 4, 0}) {
      Card c = new Card();
      c.loseAfterKey = interrupted;
      Journal j = new Journal();
      assertThrows(
          IOException.class,
          () -> Provisioner.write(new TagSession(c), template, master, "standard", false, j, j));
      Provisioner.write(new TagSession(c), template, master, "standard", true, j, j);
      assertEquals("Complete", j.stage);
      assertTrue(c.enabled);
      for (int i = 0; i < 5; i++)
        assertArrayEquals(Crypto.derive(master, c.uid, i, "standard"), c.keys[i]);
    }
  }

  @Test
  public void unknownKeysFailBeforeWrites() {
    Card c = new Card();
    c.keys[3][0] = 1;
    Journal j = new Journal();
    assertThrows(
        IOException.class,
        () -> Provisioner.write(new TagSession(c), template, master, "legacy", false, j, j));
    assertEquals(0, c.writes);
  }

  @Test
  public void mismatchedRecoveryAndFailedJournalDoNotWrite() {
    Card c = new Card();
    Journal j = new Journal();
    assertThrows(
        IOException.class,
        () -> Provisioner.write(new TagSession(c), template, master, "legacy", true, j, j));
    assertEquals(0, c.writes);
    j.reject = true;
    assertThrows(
        IOException.class,
        () -> Provisioner.write(new TagSession(c), template, master, "legacy", false, j, j));
    assertEquals(0, c.writes);
  }

  @Test
  public void completedTagRefusesFreshSetup() throws Exception {
    Card c = new Card();
    Journal j = new Journal();
    Provisioner.write(new TagSession(c), template, master, "standard", false, j, j);
    int writes = c.writes;
    assertThrows(
        IOException.class,
        () -> Provisioner.write(new TagSession(c), template, master, "standard", false, j, j));
    assertEquals(writes, c.writes);
  }

  @Test
  public void migratesAndResumesEveryAmbiguousKeyChange() throws Exception {
    byte[] old = Bytes.hex("00112233445566778899AABBCCDDEEFF");
    for (String oldMode : new String[] {"legacy", "standard"})
      for (int interrupted : new int[] {-1, 1, 2, 3, 4, 0}) {
        Card c = new Card();
        Journal j = new Journal();
        for (int i = 0; i < 5; i++) c.keys[i] = Crypto.derive(old, c.uid, i, oldMode);
        c.settings = template.settings;
        c.enabled = true;
        c.loseAfterKey = interrupted;
        if (interrupted >= 0) {
          assertThrows(
              IOException.class,
              () ->
                  Provisioner.write(
                      new TagSession(c), template, master, "legacy", old, oldMode, false, j, j));
          Provisioner.write(
              new TagSession(c), template, master, "legacy", old, oldMode, true, j, j);
        } else
          Provisioner.write(
              new TagSession(c), template, master, "legacy", old, oldMode, false, j, j);
        for (int i = 0; i < 5; i++)
          assertArrayEquals(Crypto.derive(master, c.uid, i, "legacy"), c.keys[i]);
        assertEquals(Arrays.asList(1, 2, 3, 4, 0), c.changedKeys);
        assertEquals("Complete", j.stage);
      }
  }

  @Test
  public void wrongOldMasterStopsBeforeWritesAndShowsCause() {
    Card c = new Card();
    Journal j = new Journal();
    IOException e =
        assertThrows(
            IOException.class,
            () ->
                Provisioner.write(
                    new TagSession(c), template, master, "legacy", master, "legacy", false, j, j));
    assertTrue(e.getMessage().contains("91AE"));
    assertEquals(0, c.writes);
  }

  @Test
  public void transportFailureDoesNotTryAnotherKeyOnResume() {
    Card c = new Card();
    Journal j = new Journal();
    j.uid = Bytes.hex(c.uid);
    final int[] attempts = {0};
    TagSession.Transport failing =
        apdu -> {
          if ((apdu[1] & 255) == 0x71) {
            attempts[0]++;
            throw new IOException("RF lost");
          }
          return c.transceive(apdu);
        };
    IOException e =
        assertThrows(
            IOException.class,
            () ->
                Provisioner.write(new TagSession(failing), template, master, "legacy", true, j, j));
    assertEquals("RF lost", e.getMessage());
    assertEquals(1, attempts[0]);
    assertEquals(0, c.writes);
  }
}
