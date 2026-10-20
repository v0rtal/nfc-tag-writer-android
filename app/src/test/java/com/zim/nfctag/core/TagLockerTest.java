package com.zim.nfctag.core;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Arrays;
import org.junit.Test;

public class TagLockerTest {
  final byte[] master = Bytes.hex("C9EB67DF090AFF47C3B19A2516680B9D");
  final TagTemplate template = new TagTemplate("https://example.com/tagtt");

  ProvisionerTest.Card provision() throws Exception {
    ProvisionerTest.Card card = new ProvisionerTest.Card();
    ProvisionerTest.Journal j = new ProvisionerTest.Journal();
    Provisioner.write(new TagSession(card), template, master, "legacy", false, j, j);
    return card;
  }

  @Test
  public void deniesFileChangesAndDiscardsManagementKeyPreservingSdmKeys() throws Exception {
    ProvisionerTest.Card card = provision();
    byte[][] prior = new byte[5][];
    for (int i = 0; i < 5; i++) prior[i] = card.keys[i].clone();
    ProvisionerTest.Journal j = new ProvisionerTest.Journal();
    TagLocker.lock(new TagSession(card), prior[0], card.uid, j);
    for (int f = 1; f <= 3; f++) {
      assertEquals(255, card.fileOptions(f)[1] & 255);
      assertEquals(15, card.fileOptions(f)[2] & 15);
    }
    assertEquals(14, card.settings[2] >>> 4 & 15);
    assertArrayEquals(
        Bytes.slice(template.settings, 3, template.settings.length),
        Bytes.slice(card.settings, 3, card.settings.length));
    for (int i = 1; i < 5; i++) assertArrayEquals(prior[i], card.keys[i]);
    assertFalse(Arrays.equals(prior[0], card.keys[0]));
    assertEquals("Permanently locked", j.stage);
    assertEquals(-1, card.auth);
    assertThrows(IOException.class, () -> new TagSession(card).authenticate(0, prior[0]));
    TagSession privileged = new TagSession(card);
    privileged.authenticate(0, card.keys[0]);
    assertThrows(IOException.class, () -> privileged.changeSettings(template.settings));
  }

  @Test
  public void resumesAfterLostFileLockResponses() throws Exception {
    for (int f = 1; f <= 3; f++) {
      ProvisionerTest.Card c = provision();
      byte[] management = c.keys[0].clone();
      c.loseAfterFile = f;
      ProvisionerTest.Journal j = new ProvisionerTest.Journal();
      assertThrows(
          IOException.class, () -> TagLocker.lock(new TagSession(c), management, c.uid, j));
      TagLocker.lock(new TagSession(c), management, c.uid, j);
      assertEquals("Permanently locked", j.stage);
    }
  }

  @Test
  public void lostManagementKeyResponseRemainsIrreversible() throws Exception {
    ProvisionerTest.Card c = provision();
    byte[] management = c.keys[0].clone();
    c.loseAfterKey = 0;
    ProvisionerTest.Journal j = new ProvisionerTest.Journal();
    assertThrows(IOException.class, () -> TagLocker.lock(new TagSession(c), management, c.uid, j));
    assertEquals("Discarding management key", j.stage);
    assertFalse(Arrays.equals(management, c.keys[0]));
    assertThrows(IOException.class, () -> TagLocker.lock(new TagSession(c), management, c.uid, j));
  }

  @Test
  public void unsupportedRightsOrFailedJournalStopBeforeLocking() throws Exception {
    ProvisionerTest.Card c = provision();
    byte[] management = c.keys[0].clone();
    int writes = c.writes;
    c.privateSettings[1] = 1;
    ProvisionerTest.Journal j = new ProvisionerTest.Journal();
    assertThrows(IOException.class, () -> TagLocker.lock(new TagSession(c), management, c.uid, j));
    assertEquals(writes, c.writes);
    c.privateSettings[1] = 0;
    j.reject = true;
    assertThrows(IOException.class, () -> TagLocker.lock(new TagSession(c), management, c.uid, j));
    assertEquals(writes, c.writes);
  }
}
