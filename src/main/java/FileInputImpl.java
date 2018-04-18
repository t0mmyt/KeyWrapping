import com.google.common.primitives.Longs;

import javax.crypto.SecretKey;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Iterator;

public class FileInputImpl implements Iterator<byte[]> {
    private final InputStream inputStream;
    private final PrivateKey privateKey;
    private final RecordEncryptor encryptor;
    private byte[] nextVal = null;

    public FileInputImpl(InputStream inputStream, PrivateKey privateKey) throws IOException, GeneralSecurityException {
        this.inputStream = inputStream;
        this.privateKey = privateKey;
        Long offset = readOffset();
        if (offset == null) {
            throw new EOFException("Early end of file");
        }
        SecretKey secretKey = KeyWrapper.oeapKeyUnwrap(privateKey, read(offset));
        encryptor = new AesGcmRandomIv(secretKey);
        next();
    }

    @Override
    public boolean hasNext() {
        return nextVal != null;
    }

    @Override
    public byte[] next() {
        byte[] thisVal = nextVal;
        try {
            byte[] record = readRecord();
            nextVal = record != null ? encryptor.decrypt(record) : null;
        } catch (IOException | GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
        return thisVal;
    }

    private byte[] readRecord() throws IOException {
        Long offset1 = readOffset();
        if (offset1 == null) {
            return null;
        }
        byte[] record = read(offset1);
        if (record == null) {
            return null;
        }
        Long offset2 = readOffset();
        if (offset2 == null) {
            return null;
        }
        if (!offset1.equals(offset2)) {
            throw new IOException("Offset before and after record was different");
        }
        return record;
    }

    private Long readOffset() throws IOException {
        byte[] length = read(Long.BYTES);
        return length != null ? Longs.fromByteArray(length) : null;
    }

    private byte[] read(long length) throws IOException {
        byte[] bytes = new byte[(int) length];
        if (inputStream.read(bytes) != -1) {
            return bytes;
        }
        return null;
    }
}
