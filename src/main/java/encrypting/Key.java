package encrypting;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class Key {

    private KeyPair keyPair;
    private String keyPairID;
    private String keyType;
    private int keyBits;

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public String getKeyPairID() {
        return keyPairID;
    }

    public void setKeyPairID(String keyPairID) {
        this.keyPairID = keyPairID;
    }

    public String getKeyType() {
        return keyType;
    }

    public void setKeyType(String keyType) {
        this.keyType = keyType;
    }

    public int getKeyBits() {
        return keyBits;
    }

    public void setKeyBits(int keyBits) {
        this.keyBits = keyBits;
    }

    public Key(String keyPairID, String keyType, int keyBits) {
        this.keyPairID = keyPairID;
        this.keyType = keyType;
        this.keyBits = keyBits;
        this.keyPair = generateKeyPair(this.keyType,this.keyBits);
    }

    public KeyPair generateKeyPair(String type, int bits) {
        KeyPair kp = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(type);
            kpg.initialize(bits);
            kp = kpg.generateKeyPair();

        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }
        return kp;
    }
}
