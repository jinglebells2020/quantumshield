import java.security.*;
import javax.crypto.*;

public class RSAEncrypt {
    public static void main(String[] args) throws Exception {
        // Generate RSA key pair - QUANTUM VULNERABLE
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Encrypt with RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());

        byte[] message = "secret data".getBytes();
        byte[] encrypted = cipher.doFinal(message);

        // SHA-1 digest - deprecated
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(message);

        // MD5 - broken
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] md5hash = md5.digest(message);
    }
}
