import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.*;

final public class KeyWrapper {
    private static final String KEY_WRAPPING_ALGORITHM = "RSA/NONE/OAEPPadding";
    private static final String PROVIDER = "BC";
    private static final int RSA_BITS = 2048;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private KeyWrapper() {

    }

    public static byte[] oeapKeyWrap(PublicKey publicKey, SecretKey secretKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(KEY_WRAPPING_ALGORITHM, PROVIDER);
        cipher.init(Cipher.WRAP_MODE, publicKey);
        return cipher.wrap(secretKey);
    }

    public static SecretKey oeapKeyUnwrap(PrivateKey privateKey, byte[] wrappedKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(KEY_WRAPPING_ALGORITHM, PROVIDER);
        cipher.init(Cipher.UNWRAP_MODE, privateKey);
        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static KeyPair generatePublicPrivateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_BITS);
        return keyPairGenerator.generateKeyPair();
    }
}
