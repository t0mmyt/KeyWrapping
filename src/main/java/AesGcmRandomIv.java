import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;

public class AesGcmRandomIv implements RecordEncryptor {
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final String KEY_TYPE = "AES";
    private static final int AES_BITS = 256;
    private static final int IV_BYTES = 16;
    private final Cipher cipher;
    private final SecretKey secretKey;
    private final SecureRandom secureRandomIv = SecureRandom.getInstance("NonceAndIv", "BC");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Encryptor with random key
     */
    public AesGcmRandomIv() throws GeneralSecurityException {
        this(newKey());
    }

    /**
     * Encryptor with provided key as byte[]
     */
    public AesGcmRandomIv(byte[] key) throws GeneralSecurityException {
        this(new SecretKeySpec(key, KEY_TYPE));
    }

    /**
     * Encryptor with provided key as SecretKey
     */
    public AesGcmRandomIv(SecretKey key) throws GeneralSecurityException {
        this.secretKey = key;
        cipher = Cipher.getInstance(CIPHER, "BC");
    }

    @Override
    public byte[] encrypt(byte[] record) throws GeneralSecurityException {
        IvParameterSpec iv = newIvParameterSpec();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encrypted = cipher.doFinal(record);
        byte[] encryptedWithIv = new byte[IV_BYTES + encrypted.length];
        System.arraycopy(iv.getIV(), 0, encryptedWithIv, 0, iv.getIV().length);
        System.arraycopy(encrypted, 0, encryptedWithIv, IV_BYTES, encrypted.length);
        return encryptedWithIv;
    }

    @Override
    public byte[] decrypt(byte[] record) throws GeneralSecurityException {
        byte[] iv = new byte[IV_BYTES];
        byte[] encrypted = new byte[record.length - IV_BYTES];
        System.arraycopy(record, 0, iv, 0, IV_BYTES);
        System.arraycopy(record, IV_BYTES, encrypted, 0, record.length - IV_BYTES);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return cipher.doFinal(encrypted);
    }

    public SecretKey getKey() {
        return secretKey;
    }

    private static SecretKey newKey() throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(AES_BITS);
        return keyGenerator.generateKey();
    }

    private IvParameterSpec newIvParameterSpec() {
        byte[] iv = new byte[IV_BYTES];
        secureRandomIv.nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
