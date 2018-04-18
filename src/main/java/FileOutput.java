import java.io.IOException;
import java.security.GeneralSecurityException;

public interface FileOutput {

    void writeRecord(byte[] record) throws IOException, GeneralSecurityException;

}
