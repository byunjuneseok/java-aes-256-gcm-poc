package aes256_poc;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Base64.Decoder;

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

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getCipherTextAndTag() {
        return Bytes.concat(this.cipherText, this.tag);
    }
}
