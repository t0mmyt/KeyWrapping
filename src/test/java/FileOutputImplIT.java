import com.google.common.collect.Lists;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

public class FileOutputImplIT {

    @Test
    public void testTheWorld() throws GeneralSecurityException, IOException {
        KeyPair keys = KeyWrapper.generatePublicPrivateKeyPair();
        PublicKey publicKey = keys.getPublic();
        PrivateKey privateKey = keys.getPrivate();

        String[] messages = new String[]{
                "Hello, World",
                "Foo",
                "Bar",
                "Baz"
        };

        OutputStream outputStream = new ByteArrayOutputStream();
        RecordEncryptor encryptor = new AesGcmRandomIv();

        try (FileOutputImpl output = new FileOutputImpl(outputStream, publicKey, encryptor)) {
            Arrays.stream(messages).map(String::getBytes).forEach(m -> {
                try {
                    output.writeRecord(m);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
        }

        byte[] encryptedFile = ((ByteArrayOutputStream) outputStream).toByteArray();

        ByteArrayInputStream inputStream = new ByteArrayInputStream(encryptedFile);

        FileInputImpl input = new FileInputImpl(inputStream, privateKey);

        List<byte[]> gotBack = Lists.newArrayList(input);
        List<String> gotBackStrings = gotBack.stream().map(String::new).collect(Collectors.toList());

        assertThat(gotBackStrings, equalTo(Arrays.asList(messages)));

    }

}