package com.zim.nfctag.core;

import static org.junit.Assert.*;

import java.io.IOException;
import java.lang.reflect.Field;
import org.junit.Test;

public class CoreTest {
  private static byte[] h(String x) {
    return Bytes.hex(x);
  }

  @Test
  public void selectsRegisteredNdefApplication() throws Exception {
    TagSession s =
        new TagSession(
            apdu -> {
              assertArrayEquals(h("00A4040C07D276000085010100"), apdu);
              return h("9000");
            });
    s.selectApplication();
  }

  @Test
  public void missingApplicationStopsBeforeNativeCommands() {
    int[] calls = {0};
    TagSession s =
        new TagSession(
            apdu -> {
              calls[0]++;
              assertArrayEquals(h("00A4040C07D276000085010100"), apdu);
              return h("6A82");
            });
    IOException failure = assertThrows(IOException.class, () -> s.selectApplication());
    assertEquals("Select NTAG application: tag returned 6A82", failure.getMessage());
    assertEquals(1, calls[0]);
  }

  @Test
  public void dynamicReadSelectsApplicationThenNdefFile() throws Exception {
    TagTemplate template = new TagTemplate("https://example.com/tagtt");
    int[] calls = {0};
    TagSession s =
        new TagSession(
            apdu -> {
              int step = calls[0]++;
              if (step == 0) {
                assertArrayEquals(h("00A4040C07D276000085010100"), apdu);
                return h("9000");
              }
              if (step == 1) {
                assertArrayEquals(h("00A4020C02E10400"), apdu);
                return h("9000");
              }
              assertEquals(0, apdu[0]);
              assertEquals((byte) 0xb0, apdu[1]);
              int offset = (apdu[2] & 255) * 256 + (apdu[3] & 255), length = apdu[4] & 255;
              return Bytes.join(Bytes.slice(template.file, offset, offset + length), h("9000"));
            });
    assertEquals(template.url, s.readDynamicURL());
  }

  @Test
  public void rfc4493CMAC() {
    byte[] key = h("2b7e151628aed2a6abf7158809cf4f3c");
    assertEquals("BB1D6929E95937287FA37D129B756746", Bytes.hex(Crypto.cmac(key, new byte[0])));
    assertEquals(
        "070A16B46B4D4144F79BDD9DD04A287C",
        Bytes.hex(Crypto.cmac(key, h("6bc1bee22e409f96e93d7e117393172a"))));
    assertEquals(
        "DFA66747DE9AE63030CA32611497C827",
        Bytes.hex(
            Crypto.cmac(
                key,
                h(
                    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"))));
  }

  @Test
  public void keyDerivationMatchesGo() {
    byte[] master = h("C9EB67DF090AFF47C3B19A2516680B9D"), uid = h("03030303030303");
    String[] legacy = {
      "292438328d4c26682c2ba9f55d7845d2",
      "a78399936d9887a07e7d3958ff8831f9",
      "dac1d59b625d779bc788ce502184fa9f",
      "555eec1a75dd61e7f7cf1ff5e9879767",
      "e623fff262181bca977b20cc6ce31ed7"
    };
    String[] standard = {
      "350af981f3d3dd524057ce5fce8c10b1",
      "a13086f194d7bdfd108dd11716ea2bdf",
      "85f7cc459a5b4b2f5d1a5019ded61c88",
      "412cc7388e4f9342f0463d5d8b84775b",
      "82afb204f3417ff531529fd34e807137"
    };
    for (int i = 0; i < 5; i++) {
      assertArrayEquals(h(legacy[i]), Crypto.derive(master, uid, i, "legacy"));
      assertArrayEquals(h(standard[i]), Crypto.derive(master, uid, i, "standard"));
      assertArrayEquals(new byte[16], Crypto.derive(new byte[16], uid, i, "legacy"));
    }
  }

  @Test
  public void nxpSessionKeysAndCRC() {
    byte[] a = h("13C5DB8A5930439FC3DEF9A4C675360F"), b = h("B9E2FC789B64BF237CCCAA20EC7E6E48");
    assertEquals(
        "1309C877509E5A215007FF0ED19CA564", Bytes.hex(Crypto.sessionKey(new byte[16], a, b, true)));
    assertEquals(
        "4C6626F5E72EA694202139295C7A7FC7",
        Bytes.hex(Crypto.sessionKey(new byte[16], a, b, false)));
    assertEquals("789DFADC", Bytes.hex(Crypto.jamCRC(h("F3847D627727ED3BC9C4CC050489B966"))));
    assertEquals(32, Crypto.pad(new byte[16]).length);
    assertArrayEquals(new byte[16], Crypto.unpad(Crypto.pad(new byte[16])));
  }

  @Test
  public void tagTemplateAndSettings() {
    TagTemplate t = new TagTemplate("https://example.com/tagtt");
    assertEquals(35, t.piccOffset);
    assertEquals(72, t.encOffset);
    assertEquals(110, t.macOffset);
    assertEquals(126, t.file.length);
    assertEquals(t.url, TagTemplate.decodeFile(t.file));
    assertEquals("4000E0D9F0122300004800004800004800002000006E0000", Bytes.hex(t.settings));
    assertEquals(
        "II",
        new String(
            Bytes.slice(t.file, t.encOffset, t.encOffset + 2),
            java.nio.charset.StandardCharsets.US_ASCII));
  }

  @Test
  public void rejectsInvalidURLsAndLongNDEF() {
    for (String s :
        new String[] {
          "http://example.com/tagtt",
          "https://example.com/tag",
          "https://u:p@example.com/tagtt",
          "https://example.com/tagtt?x=y",
          "https://example.com/tagtt#x",
          "https://" + new String(new char[200]).replace('\0', 'a') + ".com/tagtt"
        }) {
      assertThrows(IllegalArgumentException.class, () -> new TagTemplate(s));
    }
  }

  @Test
  public void nxpEV2FirstAPDUs() throws Exception {
    String[] request = {
      "9071000002000000",
      "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00"
    };
    String[] response = {
      "A04C124213C186F22399D33AC2A3021591AF",
      "3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F081206639100"
    };
    int[] i = {0};
    TagSession s =
        new TagSession(
            apdu -> {
              assertArrayEquals(h(request[i[0]]), apdu);
              return h(response[i[0]++]);
            },
            out -> System.arraycopy(h("13C5DB8A5930439FC3DEF9A4C675360F"), 0, out, 0, 16));
    s.authenticate(0, new byte[16]);
    assertEquals(2, i[0]);
  }

  private static void field(TagSession s, String name, Object value) throws Exception {
    Field f = TagSession.class.getDeclaredField(name);
    f.setAccessible(true);
    f.set(s, value);
  }

  private static TagSession knownSession(
      TagSession.Transport transport, String enc, String mac, String ti, int counter)
      throws Exception {
    TagSession s = new TagSession(transport);
    field(s, "encKey", h(enc));
    field(s, "macKey", h(mac));
    field(s, "ti", h(ti));
    field(s, "counter", counter);
    field(s, "authenticatedKey", 0);
    return s;
  }

  @Test
  public void nxpChangeSettingsAPDUAndResponse() throws Exception {
    TagSession s =
        knownSession(
            apdu -> {
              assertEquals(
                  "905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400",
                  Bytes.hex(apdu));
              return h("57BFF87B1241E93D9100");
            },
            "1309C877509E5A215007FF0ED19CA564",
            "4C6626F5E72EA694202139295C7A7FC7",
            "9D00C4DF",
            1);
    s.changeSettings(h("4000E0C1F121200000430000430000"));
  }

  @Test
  public void nxpKeyChanges() throws Exception {
    TagSession s =
        knownSession(
            apdu -> {
              assertEquals(
                  "90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC75D0CE20BCD1D06E600",
                  Bytes.hex(apdu));
              return h("203BB55D1089D5879100");
            },
            "4CF3CB41A22583A61E89B158D252FC53",
            "5529860B2FC5FB6154B7F28361D30BF9",
            "7614281A",
            2);
    s.changeKey(2, new byte[16], h("F3847D627727ED3BC9C4CC050489B966"));
    TagSession s0 =
        knownSession(
            apdu -> {
              assertEquals(
                  "90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A01D6FDA6610234BDED643200",
                  Bytes.hex(apdu));
              return h("9100");
            },
            "4CF3CB41A22583A61E89B158D252FC53",
            "5529860B2FC5FB6154B7F28361D30BF9",
            "7614281A",
            3);
    s0.changeKey(0, new byte[16], h("5004BF991F408672B1EF00F08F9E8647"));
    assertThrows(IOException.class, () -> s0.changeSettings(new byte[0]));
  }

  @Test
  public void missingOrWrongResponseMACInvalidatesSession() throws Exception {
    for (String response : new String[] {"9100", "00000000000000009100"}) {
      int[] count = {0};
      TagSession s =
          knownSession(
              apdu -> {
                count[0]++;
                return h(response);
              },
              "1309C877509E5A215007FF0ED19CA564",
              "4C6626F5E72EA694202139295C7A7FC7",
              "9D00C4DF",
              1);
      assertThrows(IOException.class, () -> s.changeSettings(h("0000E0")));
      assertThrows(IOException.class, () -> s.changeSettings(h("0000E0")));
      assertEquals(1, count[0]);
    }
  }

  @Test
  public void offlineTagTamperMatchesUpstream() {
    String url =
        "https://example.com/tagtt?picc_data=FDD387BF32A33A7C40CF259675B3A1E2&enc=EA050C282D8E9043E28F7A171464D697&cmac=758110182134ECE9";
    SunVerifier.Result r = SunVerifier.verify(url, new byte[16], "legacy");
    assertTrue(r.status.startsWith("Secure"));
    assertThrows(
        IllegalArgumentException.class,
        () -> SunVerifier.verify(url.replace("758110", "758111"), new byte[16], "legacy"));
    assertThrows(
        IllegalArgumentException.class,
        () -> SunVerifier.verify(url + "&cmac=00", new byte[16], "legacy"));
  }

  @Test
  public void plainFileFailureInvalidatesSession() throws Exception {
    for (boolean reading : new boolean[] {true, false}) {
      final int[] calls = {0};
      TagSession session =
          knownSession(
              apdu -> {
                calls[0]++;
                throw new IOException("RF lost");
              },
              "1309C877509E5A215007FF0ED19CA564",
              "4C6626F5E72EA694202139295C7A7FC7",
              "9D00C4DF",
              1);
      assertThrows(
          IOException.class,
          () -> {
            if (reading) session.readStatic(0, 2);
            else session.writeFile(0, new byte[2]);
          });
      assertThrows(IOException.class, () -> session.changeSettings(h("0000E0")));
      assertEquals(1, calls[0]);
    }
  }

  @Test
  public void ndefBoundsAreCheckedBeforeTransport() throws Exception {
    TagSession session =
        knownSession(
            apdu -> {
              throw new AssertionError("Unexpected NFC write");
            },
            "1309C877509E5A215007FF0ED19CA564",
            "4C6626F5E72EA694202139295C7A7FC7",
            "9D00C4DF",
            1);
    assertThrows(IOException.class, () -> session.writeFile(255, new byte[2]));
    assertThrows(IOException.class, () -> session.readStatic(255, 2));
  }
}
