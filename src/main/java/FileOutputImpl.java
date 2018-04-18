import com.google.common.primitives.Longs;

import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

public class FileOutputImpl implements FileOutput, AutoCloseable {
    private final PublicKey publicKey;
    private final OutputStream outputStream;
    private final RecordEncryptor encryptor;

    public FileOutputImpl(OutputStream outputStream, PublicKey publicKey, RecordEncryptor encryptor)
            throws GeneralSecurityException, IOException {
        this.outputStream = outputStream;
        this.publicKey = publicKey;
        this.encryptor = encryptor;
        writeWrappedKeyHeader(outputStream);
    }

    @Override
    public void writeRecord(byte[] record) throws IOException {
        try {
            byte[] encrypted = encryptor.encrypt(record);
            byte[] length = Longs.toByteArray(encrypted.length);
            outputStream.write(length);
            outputStream.write(encrypted);
            outputStream.write(length);
        } catch (GeneralSecurityException e) {
            // TODO - Should this be added to the signature or is IOException fine
            throw new IOException(e);
        }
    }

    @Override
    public void close() throws IOException {
        outputStream.close();
    }

    private void writeWrappedKeyHeader(OutputStream outputStream) throws GeneralSecurityException, IOException {
        byte[] wrappedSecretKey = KeyWrapper.oeapKeyWrap(this.publicKey, this.encryptor.getKey());
        outputStream.write(Longs.toByteArray(wrappedSecretKey.length));
        outputStream.write(wrappedSecretKey);
        outputStream.flush();
    }
}
