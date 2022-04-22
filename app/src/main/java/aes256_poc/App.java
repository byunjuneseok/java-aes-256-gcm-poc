package aes256_poc;
import java.util.Base64;
import java.util.Base64.Decoder;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class App {
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;

    public static byte[] getKey() {
        String encodedKey = System.getenv("BASE64_ENCODED_KEY");
        Decoder decoder = Base64.getDecoder();

        byte[] decodedKey = decoder.decode(encodedKey);
        if (decodedKey.length != 32) {
            throw new IllegalArgumentException();
        }
        return decodedKey;
    }


    public static String decrypt(byte[] cipherText, byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        SecretKeySpec keySpec = new SecretKeySpec(getKey(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText);
    }

    public static void main(String[] args) throws Exception {
        String queriedField = "v=1,a=aes256gcm,3uiCUhKGdcIbcZcXU5wCzw==,t6YzJ8BWI7stb+U=,R1kgOsyI/vJRwbX2cN9/bg==";
        EncryptedField field = new EncryptedField(queriedField);

        String text = decrypt(field.getCipherTextAndTag(), field.getNonce());
        System.out.println(text);
    }
}
