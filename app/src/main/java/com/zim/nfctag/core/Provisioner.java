package com.zim.nfctag.core;

import java.io.IOException;
import java.security.MessageDigest;
import java.util.Arrays;

public final class Provisioner {
  public interface Observer {
    void progress(String message);

    // Commit before mutations; stored metadata lets the same setup resume after interruption.
    void checkpoint(String uid, String stage) throws IOException;
  }

  public interface Recovery {
    boolean permits(String uid);
  }

  public static String write(
      TagSession session,
      TagTemplate template,
      byte[] master,
      String mode,
      boolean resume,
      Recovery recovery,
      Observer observer)
      throws IOException {
    return write(session, template, master, mode, null, "legacy", resume, recovery, observer);
  }

  public static String write(
      TagSession session,
      TagTemplate template,
      byte[] master,
      String mode,
      byte[] oldMaster,
      String oldMode,
      boolean resume,
      Recovery recovery,
      Observer observer)
      throws IOException {
    if (Arrays.equals(master, new byte[16]))
      throw new IllegalArgumentException("Choose a nonzero master key");
    observer.progress("Selecting NTAG 424 DNA application…");
    session.selectApplication();
    byte[] publicUid = session.version();
    String uidHex = Bytes.hex(publicUid);
    if (publicUid[0] != 4)
      throw new IOException("Factory UID is unavailable; Random ID tags are unsupported");
    if (resume && !recovery.permits(uidHex))
      throw new IOException(
          "No matching interrupted setup for this UID, URL, master key and derivation mode");
    byte[][] target = new byte[5][], current = new byte[5][];
    try {
      for (int i = 0; i < 5; i++) target[i] = Crypto.derive(master, publicUid, i, mode);
      observer.progress("Checking tag and existing keys…");
      // Authenticate every slot before any write, rather than assuming key versions imply factory
      // keys.
      for (int i = 0; i < 5; i++) {
        session.selectApplication();
        if (resume) {
          try {
            session.authenticate(i, target[i]);
            current[i] = target[i];
            continue;
          } catch (TagSession.StatusException e) {
            if (e.status != 0x91ae) throw e;
            session.selectApplication();
          }
        }
        byte[] existing =
            oldMaster == null ? new byte[16] : Crypto.derive(oldMaster, publicUid, i, oldMode);
        try {
          session.authenticate(i, existing);
          current[i] = existing;
        } catch (IOException e) {
          throw new IOException(
              "Cannot authenticate key "
                  + i
                  + " with "
                  + (oldMaster == null
                      ? "the factory key"
                      : "the old master key and derivation mode")
                  + ". No new writes performed. "
                  + e.getMessage(),
              e);
        }
      }
      session.selectApplication();
      session.authenticate(0, current[0]);
      if (!MessageDigest.isEqual(session.uid(), publicUid))
        throw new IOException("Authenticated UID does not match the tag");
      byte[] settings = session.fileSettings();
      if (settings.length < 7
          || settings[0] != 0
          || (settings[2] & 15) != 0
          || (settings[4] & 255) != 0
          || (settings[5] & 255) != 1
          || settings[6] != 0)
        throw new IOException("Unsupported NDEF file or management permission");
      // NXP TagTamper factory NDEF rights are RW=E, Change=0, Read=E, Write=E.
      // Also accept the key-0 write variant used by some supplied tags (all keys were checked
      // above).
      byte[] fileOptions = Bytes.slice(settings, 1, 4);
      if (!resume
          && oldMaster == null
          && (!Arrays.equals(fileOptions, Bytes.hex("00E0EE"))
              && !Arrays.equals(fileOptions, Bytes.hex("0000E0"))))
        throw new IOException("Tag is already configured. Use a fresh tag.");
      observer.checkpoint(uidHex, "Preparing NDEF");
      observer.progress("Writing URL… keep the tag still");
      session.changeSettings(Bytes.hex("0000E0"));
      session.writeFile(0, new byte[2]);
      session.writeFile(2, Bytes.slice(template.file, 2, template.file.length));
      if (!Arrays.equals(
          session.readStatic(2, template.file.length - 2),
          Bytes.slice(template.file, 2, template.file.length)))
        throw new IOException("NDEF readback mismatch");
      session.writeFile(0, Bytes.slice(template.file, 0, 2));
      for (int i = 1; i < 5; i++) {
        if (!MessageDigest.isEqual(current[i], target[i])) {
          observer.checkpoint(uidHex, "Changing key " + i);
          observer.progress("Setting tag key " + i + " of 4…");
          session.changeKey(i, current[i], target[i]);
          current[i] = target[i];
        }
      }
      observer.checkpoint(uidHex, "Configuring SDM");
      observer.progress("Configuring encrypted tamper mirroring…");
      session.changeSettings(template.settings);
      byte[] configured = session.fileSettings();
      byte[] expected =
          Bytes.join(
              new byte[] {0},
              Bytes.slice(template.settings, 0, 3),
              Bytes.le(256, 3),
              Bytes.slice(template.settings, 3, template.settings.length));
      if (!Arrays.equals(configured, expected))
        throw new IOException("SDM settings readback mismatch");
      observer.checkpoint(uidHex, "Enabling tamper detection");
      observer.progress("Enabling tamper detection…");
      session.enableTamper();
      if (!MessageDigest.isEqual(current[0], target[0])) {
        observer.checkpoint(uidHex, "Changing management key");
        observer.progress("Securing management key…");
        session.changeKey(0, current[0], target[0]);
      }
      session.selectApplication();
      session.authenticate(0, target[0]);
      if (!MessageDigest.isEqual(session.uid(), publicUid))
        throw new IOException("Final authentication failed");
      // Reauthenticate each new key; failure remains resumable with the same master secret.
      for (int i = 1; i < 5; i++) {
        session.selectApplication();
        session.authenticate(i, target[i]);
      }
      observer.checkpoint(uidHex, "Complete");
      observer.progress("Written successfully. Remove the tag, then tap Verify tag.");
      return uidHex;
    } finally {
      // Recovery derives these values again from user input; never retain per-tag
      // working keys after success or failure. Some current slots alias target slots.
      for (byte[] key : target) if (key != null) Arrays.fill(key, (byte) 0);
      for (byte[] key : current) if (key != null) Arrays.fill(key, (byte) 0);
    }
  }
}
