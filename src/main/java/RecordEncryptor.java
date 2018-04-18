import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public interface RecordEncryptor {

    SecretKey getKey();

    byte[] encrypt(byte[] unencrypted) throws GeneralSecurityException;

    byte[] decrypt(byte[] encrypted) throws GeneralSecurityException;

}
