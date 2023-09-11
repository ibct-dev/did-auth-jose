import CryptoSuite, { Encrypter, Signer, SymmetricEncrypter, PublicKeyConstructors } from '../../interfaces/CryptoSuite';
/**
 * Encrypter plugin for Advanced Encryption Standard symmetric keys
 */
export default class AesCryptoSuite implements CryptoSuite {
    /** Encryption algorithms */
    getEncrypters(): {
        [algorithm: string]: Encrypter;
    };
    /** Signing algorithms */
    getSigners(): {
        [algorithm: string]: Signer;
    };
    getKeyConstructors(): PublicKeyConstructors;
    getSymmetricEncrypters(): {
        [algorithm: string]: SymmetricEncrypter;
    };
    /**
     * Given the encryption parameters, returns the AES CBC HMAC SHA2 encryption function
     * @param keySize Size of the keys
     * @param hashSize Size of the SHA2 hash
     * @returns a SymmetricEncrypter encrypt function
     */
    private encryptAesCbcHmacSha2;
    /**
     * Given the decryption parameters, returns an AES CBC HMAC SHA2 decryption function
     * @param keySize Size of the keys
     * @param hashSize Size of the SHA2 hash
     * @returns a SymmetricEncrypter decrypt function
     */
    private decryptAesCbcHmacSha2;
    /**
     * Given the encryption parameters, returns the AES GCM encryption function
     * @param keySize Size of the keys
     * @returns a SymmetricEncrypter encrypt function
     */
    private encryptAesGcm;
    /**
     * Given the decryption parameters, returns an AES GCM decryption function
     * @param keySize Size of the keys
     * @returns a SymmetricEncrypter decrypt function
     */
    private decryptAesGcm;
    /**
     * Generates the HMAC Tag
     * @param hashSize HMAC hash size
     * @param keySize HMAC tag size
     * @param mackey MAC key
     * @param additionalAuthenticatedData Additional authenticated data
     * @param initializationVector initialization vector
     * @param ciphertext encrypted data
     * @returns HMAC Tag
     */
    private generateHmacTag;
    /**
     * Generates the full HMac
     * @param hashSize HMAC hash size
     * @param mackey MAC key
     * @param additionalAuthenticatedData Additional authenticated data
     * @param initializationVector initialization vector
     * @param ciphertext encrypted data
     * @returns HMAC in full
     */
    private generateHmac;
    /**
     * Gets the Additional Authenticated Data length in Big Endian notation
     * @param additionalAuthenticatedData Additional authenticated data
     * @return Additional Authenticated Data returned as a base64 big endian unsigned integer
     */
    private getAdditionalAuthenticatedDataLength;
    /**
     * Generates a symmetric key
     * @param bits Size in bits of the key
     */
    private generateSymmetricKey;
    /**
     * Generates an initialization vector
     * @param bits Size in bits of the initialization vector
     */
    private generateInitializationVector;
}
