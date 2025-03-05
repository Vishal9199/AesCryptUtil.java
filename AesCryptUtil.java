import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
 
public class AesCryptUtil {
   public static final int AES_KEY_SIZE = 256;
   public static final int GCM_TAG_LENGTH = 16;
   public static final int IV_SIZE = 16;
   public byte[] IV = null;
   private Cipher encCipher;
   private Cipher decCipher;
   private SecretKey secretKey;
 
   public AesCryptUtil(String workingKey) throws Exception {
      this.secretKey = new SecretKeySpec(workingKey.getBytes(), 0, workingKey.getBytes().length, "AES");
      this.encCipher = Cipher.getInstance("AES/GCM/NoPadding");
      this.decCipher = Cipher.getInstance("AES/GCM/NoPadding");
   }
 
   public String encrypt(String pPlainText) throws Exception {
      this.IV = new byte[16];
      SecureRandom vRandom = new SecureRandom();
      vRandom.nextBytes(this.IV);
      System.out.println("IV HEX: " + asHex(this.IV));
      this.encCipher.init(1, this.secretKey, new GCMParameterSpec(128, this.IV));
      byte[] encData = this.encCipher.doFinal(pPlainText.getBytes());
      System.out.println("CIPHER HEX: " + asHex(encData));
      return asHex(this.IV) + asHex(encData);
   }
 
   public String decrypt(String pEncryptedText) throws Exception {
      String encodedIV = pEncryptedText.substring(0, 32);
      this.IV = hexToByte(encodedIV);
      pEncryptedText = pEncryptedText.substring(32, pEncryptedText.length());
      this.decCipher.init(2, this.secretKey, new GCMParameterSpec(128, this.IV));
      byte[] decodedBytes = hexToByte(pEncryptedText);
      byte[] decryptedData = this.decCipher.doFinal(decodedBytes);
      return new String(decryptedData);
   }
 
   public static byte[] hexToByte(String hexString) {
      int len = hexString.length();
      byte[] ba = new byte[len / 2];
 
      for(int i = 0; i < len; i += 2) {
         ba[i / 2] = (byte)((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
      }
 
      return ba;
   }
 
   public static String asHex(byte[] buf) {
      StringBuffer strbuf = new StringBuffer(buf.length * 2);
 
      for(int i = 0; i < buf.length; ++i) {
         if ((buf[i] & 255) < 16) {
            strbuf.append("0");
         }
 
         strbuf.append(Long.toString((long)(buf[i] & 255), 16));
      }
 
      return strbuf.toString();
   }
   public static void main(String[] args) {
    try {
       // Replace with a 32-character key for AES-256
       String workingKey = "A9523C140318E2D086F5817B51252BAF";
       AesCryptUtil aesUtil = new AesCryptUtil(workingKey);
 
       // Example plaintext
       String plainText = "merchant_id=215101&order_id=TR261A177&currency=OMR&amount=1.001";
       System.out.println("Original Text: " + plainText);
 
       // Encrypt the plaintext
       String encryptedText = aesUtil.encrypt(plainText);
       System.out.println("Encrypted Text: " + encryptedText);
 
       // Decrypt the ciphertext
       String decryptedText = aesUtil.decrypt(encryptedText);
       System.out.println("Decrypted Text: " + decryptedText);
 
    } catch (Exception e) {
       e.printStackTrace();
    }
 }
}
