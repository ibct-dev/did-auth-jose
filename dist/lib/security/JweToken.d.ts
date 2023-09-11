/// <reference types="node" />
import JoseToken from './JoseToken';
import PublicKey from '../security/PublicKey';
import PrivateKey from '../security/PrivateKey';
import CryptoFactory from '../CryptoFactory';
/**
 * JWE in flattened json format
 */
export declare type FlatJsonJwe = {
    /** The protected (integrity) header. */
    protected?: string;
    /** The unprotected (unverified) header. */
    unprotected?: {
        [key: string]: string;
    };
    /** Contain the value BASE64URL(JWE Encrypted Key) */
    encrypted_key: string;
    /** Contains the initial vector used for encryption */
    iv: string;
    /** The encrypted data */
    ciphertext: string;
    /** Contain the value BASE64URL(JWE Authentication Tag) */
    tag: string;
    /**  Contains the additional value */
    aad?: string;
};
/**
 * Class for performing JWE encryption operations.
 * This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.
 */
export default class JweToken extends JoseToken {
    protected cryptoFactory: CryptoFactory;
    private readonly encryptedKey;
    private readonly iv;
    private readonly tag;
    private readonly aad;
    constructor(content: string | object, cryptoFactory: CryptoFactory);
    /**
     * Encrypts the original content from construction into a JWE compact serialized format
     * using the given key in JWK JSON object format.Content encryption algorithm is hardcoded to 'A128GCM'.
     *
     * @returns Buffer of the original content encrypted in JWE compact serialized format.
     */
    encrypt(jwk: PublicKey, additionalHeaders?: {
        [header: string]: string;
    }): Promise<Buffer>;
    /**
     * Encrypts the original content from construction into a JWE JSON serialized format using
     * the given key in JWK JSON object format. Content encryption algorithm is hardcoded to 'A128GCM'.
     *
     * @returns Buffer of the original content encrytped in JWE flattened JSON serialized format.
     */
    encryptAsFlattenedJson(jwk: PublicKey, options?: {
        /** The unprotected (unverified) header. */
        unprotected?: {
            [key: string]: any;
        };
        /** The protected (integrity) header. */
        protected?: {
            [key: string]: any;
        };
        /**  Contains the additional value */
        aad?: string | Buffer;
    }): Promise<FlatJsonJwe>;
    /**
     * Encrypts the given content encryption key using the specified algorithm and asymmetric public key.
     *
     * @param keyEncryptionAlgorithm Asymmetric encryption algorithm to be used.
     * @param keyBuffer The content encryption key to be encrypted.
     * @param jwk The asymmetric public key used to encrypt the content encryption key.
     */
    private encryptContentEncryptionKey;
    /**
     * Decrypts the original JWE using the given key in JWK JSON object format.
     *
     * @returns Decrypted plaintext of the JWE
     */
    decrypt(jwk: PrivateKey): Promise<string>;
    /**
     * Converts the JWE from the constructed type into a Compact JWE
     */
    toCompactJwe(): string;
    /**
     * Converts the JWE from the constructed type into a Flat JSON JWE
     * @param headers unprotected headers to use
     */
    toFlattenedJsonJwe(headers?: {
        [member: string]: any;
    }): FlatJsonJwe;
}
