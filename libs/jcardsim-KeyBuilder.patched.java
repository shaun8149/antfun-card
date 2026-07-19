/*
 * Decompiled with CFR 0.152.
 */
package javacard.security;

import com.licel.jcardsim.crypto.DSAPrivateKeyImpl;
import com.licel.jcardsim.crypto.DSAPublicKeyImpl;
import com.licel.jcardsim.crypto.ECPrivateKeyImpl;
import com.licel.jcardsim.crypto.ECPublicKeyImpl;
import com.licel.jcardsim.crypto.KeyImpl;
import com.licel.jcardsim.crypto.RSAKeyImpl;
import com.licel.jcardsim.crypto.RSAPrivateCrtKeyImpl;
import com.licel.jcardsim.crypto.SymmetricKeyImpl;
import javacard.security.CryptoException;
import javacard.security.Key;

public class KeyBuilder {
    public static final byte TYPE_DES_TRANSIENT_RESET = 1;
    public static final byte TYPE_DES_TRANSIENT_DESELECT = 2;
    public static final byte TYPE_DES = 3;
    public static final byte TYPE_RSA_PUBLIC = 4;
    public static final byte TYPE_RSA_PRIVATE = 5;
    public static final byte TYPE_RSA_CRT_PRIVATE = 6;
    public static final byte TYPE_DSA_PUBLIC = 7;
    public static final byte TYPE_DSA_PRIVATE = 8;
    public static final byte TYPE_EC_F2M_PUBLIC = 9;
    public static final byte TYPE_EC_F2M_PRIVATE = 10;
    public static final byte TYPE_EC_FP_PUBLIC = 11;
    public static final byte TYPE_EC_FP_PRIVATE = 12;
    public static final byte TYPE_AES_TRANSIENT_RESET = 13;
    public static final byte TYPE_AES_TRANSIENT_DESELECT = 14;
    public static final byte TYPE_AES = 15;
    public static final byte TYPE_KOREAN_SEED_TRANSIENT_RESET = 16;
    public static final byte TYPE_KOREAN_SEED_TRANSIENT_DESELECT = 17;
    public static final byte TYPE_KOREAN_SEED = 18;
    public static final byte TYPE_HMAC_TRANSIENT_RESET = 19;
    public static final byte TYPE_HMAC_TRANSIENT_DESELECT = 20;
    public static final byte TYPE_HMAC = 21;
    public static final byte TYPE_RSA_PRIVATE_TRANSIENT_RESET = 22;
    public static final byte TYPE_RSA_PRIVATE_TRANSIENT_DESELECT = 23;
    public static final byte TYPE_RSA_CRT_PRIVATE_TRANSIENT_RESET = 24;
    public static final byte TYPE_RSA_CRT_PRIVATE_TRANSIENT_DESELECT = 25;
    public static final byte TYPE_DSA_PRIVATE_TRANSIENT_RESET = 26;
    public static final byte TYPE_DSA_PRIVATE_TRANSIENT_DESELECT = 27;
    public static final byte TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET = 28;
    public static final byte TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT = 29;
    public static final byte TYPE_EC_FP_PRIVATE_TRANSIENT_RESET = 30;
    public static final byte TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT = 31;
    public static final byte TYPE_DH_PUBLIC = 32;
    public static final byte TYPE_DH_PUBLIC_TRANSIENT_DESELECT = 33;
    public static final byte TYPE_DH_PUBLIC_TRANSIENT_RESET = 34;
    public static final byte TYPE_DH_PRIVATE = 35;
    public static final byte TYPE_DH_PRIVATE_TRANSIENT_DESELECT = 36;
    public static final byte TYPE_DH_PRIVATE_TRANSIENT_RESET = 37;
    public static final byte ALG_TYPE_DES = 1;
    public static final byte ALG_TYPE_AES = 2;
    public static final byte ALG_TYPE_DSA_PUBLIC = 3;
    public static final byte ALG_TYPE_DSA_PRIVATE = 4;
    public static final byte ALG_TYPE_EC_F2M_PUBLIC = 5;
    public static final byte ALG_TYPE_EC_F2M_PRIVATE = 6;
    public static final byte ALG_TYPE_EC_FP_PUBLIC = 7;
    public static final byte ALG_TYPE_EC_FP_PRIVATE = 8;
    public static final byte ALG_TYPE_HMAC = 9;
    public static final byte ALG_TYPE_KOREAN_SEED = 10;
    public static final byte ALG_TYPE_RSA_PUBLIC = 11;
    public static final byte ALG_TYPE_RSA_PRIVATE = 12;
    public static final byte ALG_TYPE_RSA_CRT_PRIVATE = 13;
    public static final byte ALG_TYPE_DH_PUBLIC = 14;
    public static final byte ALG_TYPE_DH_PRIVATE = 15;
    public static final byte ALG_TYPE_EC_F2M_PARAMETERS = 16;
    public static final byte ALG_TYPE_EC_FP_PARAMETERS = 17;
    public static final byte ALG_TYPE_DSA_PARAMETERS = 18;
    public static final byte ALG_TYPE_DH_PARAMETERS = 19;
    public static final short LENGTH_DES = 64;
    public static final short LENGTH_DES3_2KEY = 128;
    public static final short LENGTH_DES3_3KEY = 192;
    public static final short LENGTH_RSA_512 = 512;
    public static final short LENGTH_RSA_736 = 736;
    public static final short LENGTH_RSA_768 = 768;
    public static final short LENGTH_RSA_896 = 896;
    public static final short LENGTH_RSA_1024 = 1024;
    public static final short LENGTH_RSA_1280 = 1280;
    public static final short LENGTH_RSA_1536 = 1536;
    public static final short LENGTH_RSA_1984 = 1984;
    public static final short LENGTH_RSA_2048 = 2048;
    public static final short LENGTH_RSA_3072 = 3072;
    public static final short LENGTH_RSA_4096 = 4096;
    public static final short LENGTH_DSA_512 = 512;
    public static final short LENGTH_DSA_768 = 768;
    public static final short LENGTH_DSA_1024 = 1024;
    public static final short LENGTH_EC_FP_112 = 112;
    public static final short LENGTH_EC_F2M_113 = 113;
    public static final short LENGTH_EC_FP_128 = 128;
    public static final short LENGTH_EC_F2M_131 = 131;
    public static final short LENGTH_EC_FP_160 = 160;
    public static final short LENGTH_EC_F2M_163 = 163;
    public static final short LENGTH_EC_FP_192 = 192;
    public static final short LENGTH_EC_F2M_193 = 193;
    public static final short LENGTH_EC_FP_224 = 224;
    public static final short LENGTH_EC_FP_256 = 256;
    public static final short LENGTH_EC_FP_384 = 384;
    public static final short LENGTH_EC_FP_521 = 521;
    public static final short LENGTH_AES_128 = 128;
    public static final short LENGTH_AES_192 = 192;
    public static final short LENGTH_AES_256 = 256;
    public static final short LENGTH_KOREAN_SEED_128 = 128;
    public static final short LENGTH_HMAC_SHA_1_BLOCK_64 = 64;
    public static final short LENGTH_HMAC_SHA_256_BLOCK_64 = 64;
    public static final short LENGTH_HMAC_SHA_384_BLOCK_128 = 128;
    public static final short LENGTH_HMAC_SHA_512_BLOCK_128 = 128;
    public static final short LENGTH_DH_1024 = 1024;
    public static final short LENGTH_DH_2048 = 2048;

    public static Key buildKey(byte keyType, short keyLength, boolean keyEncryption) throws CryptoException {
        KeyImpl key = null;
        switch (keyType) {
            case 1: 
            case 2: 
            case 3: {
                if (keyLength != 64 && keyLength != 128 && keyLength != 192) {
                    CryptoException.throwIt((short)1);
                }
                key = new SymmetricKeyImpl(keyType, keyLength);
                break;
            }
            case 4: {
                key = new RSAKeyImpl(false, keyLength);
                break;
            }
            case 5: {
                key = new RSAKeyImpl(true, keyLength);
                break;
            }
            case 6: {
                key = new RSAPrivateCrtKeyImpl(keyLength);
                break;
            }
            case 7: {
                key = new DSAPublicKeyImpl(keyLength);
                break;
            }
            case 8: {
                key = new DSAPrivateKeyImpl(keyLength);
                break;
            }
            case 9: {
                key = new ECPublicKeyImpl(keyType, keyLength);
                break;
            }
            case 10: {
                key = new ECPrivateKeyImpl(keyType, keyLength);
                break;
            }
            case 11: {
                key = new ECPublicKeyImpl(keyType, keyLength);
                break;
            }
            case 12: {
                key = new ECPrivateKeyImpl(keyType, keyLength);
                break;
            }
            case 28: // TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET
            case 29: // TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT
            {
                // jcardsim has no real transient semantics; map to persistent EC F2M private
                key = new ECPrivateKeyImpl(TYPE_EC_F2M_PRIVATE, keyLength);
                break;
            }
            case 30: // TYPE_EC_FP_PRIVATE_TRANSIENT_RESET
            case 31: // TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT
            {
                // jcardsim has no real transient semantics; map to persistent EC FP private
                key = new ECPrivateKeyImpl(TYPE_EC_FP_PRIVATE, keyLength);
                break;
            }
            case 13:
            case 14: 
            case 15: {
                if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
                    CryptoException.throwIt((short)1);
                }
                key = new SymmetricKeyImpl(keyType, keyLength);
                break;
            }
            case 19: 
            case 20: 
            case 21: {
                key = new SymmetricKeyImpl(keyType, keyLength);
                break;
            }
            default: {
                CryptoException.throwIt((short)3);
            }
        }
        return key;
    }

    public static Key buildKey(byte by, byte by2, short s, boolean bl) throws CryptoException {
        return null;
    }

    public static Key buildKeyWithSharedDomain(byte by, byte by2, Key key, boolean bl) throws CryptoException {
        return null;
    }
}

