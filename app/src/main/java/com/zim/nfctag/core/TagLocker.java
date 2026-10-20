package com.zim.nfctag.core;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

/** Irreversible file access denial plus destruction of the management credential. */
public final class TagLocker {
  private TagLocker() {}

  public static void lock(
      TagSession session, byte[] managementKey, byte[] uid, Provisioner.Observer observer)
      throws IOException {
    String uidHex = Bytes.hex(uid);
    session.selectApplication();
    session.authenticate(0, managementKey);
    if (!Arrays.equals(session.uid(), uid)) throw new IOException("Lock UID mismatch");
    byte[][] settings = new byte[3][];
    // Check every file before the first irreversible command. Preserve all read and SDM settings.
    for (int file = 1; file <= 3; file++) {
      byte[] actual = session.fileSettings(file);
      if (actual.length < 7 || actual[0] != 0)
        throw new IOException("Unsupported file for permanent lock: " + file);
      int change = actual[2] & 15;
      if (change != 0 && change != 15)
        throw new IOException("File " + file + " cannot be locked with management key 0");
      // GetFileSettings starts with FileType, FileOption, then the two access bytes.
      // A previously frozen file is resumable only if BOTH write paths are denied.
      if (change == 15 && ((actual[2] & 255) != 255 || (actual[3] & 15) != 15))
        throw new IOException("File " + file + " settings are frozen but writes remain possible");
      settings[file - 1] =
          Bytes.join(Bytes.slice(actual, 1, 4), Bytes.slice(actual, 7, actual.length));
      settings[file - 1][1] = (byte) 0xff;
      settings[file - 1][2] |= 15;
    }
    observer.checkpoint(uidHex, "Permanent lock started");
    for (int file = 1; file <= 3; file++) {
      observer.progress("Permanently locking file " + file + " of 3…");
      byte[] actual = session.fileSettings(file);
      if ((actual[2] & 15) != 15) session.changeSettings(file, settings[file - 1]);
      byte[] result = session.fileSettings(file);
      byte[] expected =
          Bytes.join(
              new byte[] {0},
              Bytes.slice(settings[file - 1], 0, 3),
              Bytes.slice(actual, 4, 7),
              Bytes.slice(settings[file - 1], 3, settings[file - 1].length));
      if (!Arrays.equals(result, expected))
        throw new IOException("Permanent lock readback failed for file " + file);
    }
    byte[] discarded = new byte[16];
    new SecureRandom().nextBytes(discarded);
    try {
      observer.checkpoint(uidHex, "Discarding management key");
      observer.progress("Permanently disabling key changes…");
      session.changeKey(0, managementKey, discarded);
      session.selectApplication();
      session.authenticate(0, discarded);
    } finally {
      Arrays.fill(discarded, (byte) 0);
    }
    session.selectApplication(); // End the last privileged session before reporting completion.
    observer.checkpoint(uidHex, "Permanently locked");
  }
}
