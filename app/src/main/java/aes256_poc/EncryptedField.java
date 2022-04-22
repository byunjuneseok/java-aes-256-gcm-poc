package aes256_poc;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import com.google.common.primitives.Bytes;

public class EncryptedField {

    public String version;
    public String algorithm;
    private byte[] nonce;
    private byte[] cipherText;
    private byte[] tag;


    public EncryptedField(String fieldString) {
        List<String> parsedFieldString = Arrays.asList(fieldString.split(","));

        Decoder decoder = Base64.getDecoder();
        this.version = parsedFieldString.get(0);
        this.algorithm = parsedFieldString.get(1);
        this.nonce = decoder.decode(parsedFieldString.get(2));
        this.cipherText = decoder.decode(parsedFieldString.get(3));
        this.tag = decoder.decode(parsedFieldString.get(4));
    }

    public EncryptedField(byte[] nonce, byte[] cipherText) {
        this.version = "v=1";
        this.algorithm = "a=aes256gcm";
        this.nonce = nonce;

        int cipherTextLength = cipherText.length - 16;
        this.cipherText = Arrays.copyOfRange(cipherText, 0, cipherTextLength);
        this.tag = Arrays.copyOfRange(cipherText, cipherTextLength, cipherText.length);
    }

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getCipherTextAndTag() {
        return Bytes.concat(this.cipherText, this.tag);
    }

    public String getField() {
        Encoder encoder = Base64.getEncoder();

        return String.format(
            "v=1,a=aes256gcm,%s,%s,%s",
            encoder.encodeToString(this.nonce),
            encoder.encodeToString(this.cipherText),
            encoder.encodeToString(this.tag)
        );
    }
}
