import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

public class DESExample {
    public static void main(String[] args) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        Cipher cipher = Cipher.getInstance("DES");
    }
}
