import com.zim.nfctag.core.Bytes;
import com.zim.nfctag.core.Crypto;
import com.zim.nfctag.core.TagTemplate;
import java.util.Arrays;

/** Deterministic public test messages, not provisioning secrets. */
public class GenerateInteropVectors {
  public static void main(String[] args) {
    TagTemplate template = new TagTemplate("https://example.com/tagtt");
    byte[] uid = Bytes.hex("04112233445566"), counter = {123, 0, 0};
    String masterHex = "C9EB67DF090AFF47C3B19A2516680B9D";
    byte[] master = Bytes.hex(masterHex),
        piccPlain = Bytes.join(new byte[] {(byte) 0xc7}, uid, counter, new byte[5]);
    System.out.println("[");
    boolean first = true;
    for (String mode : new String[] {"legacy", "standard"}) {
      if (!first) System.out.println(",");
      first = false;
      byte[] meta = Crypto.derive(master, uid, 1, mode),
          key = Crypto.derive(master, uid, 2, mode),
          context = Bytes.join(uid, counter);
      byte[] picc = Crypto.aes(meta, new byte[16], piccPlain, true);
      byte[] encKey = Crypto.cmac(key, Bytes.join(Bytes.hex("C33C00010080"), context));
      byte[] iv = Crypto.aes(encKey, new byte[16], Bytes.join(counter, new byte[13]), true);
      // The chip mirrors CC before encrypting the first half of the actual template placeholder.
      byte[] plain = Arrays.copyOfRange(template.file, template.encOffset, template.encOffset + 16);
      plain[0] = 'C';
      plain[1] = 'C';
      byte[] file = Crypto.aes(encKey, iv, plain, true);
      byte[] macKey = Crypto.cmac(key, Bytes.join(Bytes.hex("3CC300010080"), context));
      byte[] signature =
          Crypto.shortMac(Crypto.cmac(macKey, Bytes.ascii(Bytes.hex(file) + "&cmac=")));
      String url =
          template.endpoint
              + "?picc_data="
              + Bytes.hex(picc)
              + "&enc="
              + Bytes.hex(file)
              + "&cmac="
              + Bytes.hex(signature);
      System.out.print(
          "{\"mode\":\""
              + mode
              + "\",\"master\":\""
              + masterHex
              + "\",\"url\":\""
              + url
              + "\",\"uid\":\""
              + Bytes.hex(uid)
              + "\",\"counter\":123,\"plaintext\":\""
              + Bytes.hex(plain)
              + "\"}");
    }
    System.out.println("\n]");
  }
}
