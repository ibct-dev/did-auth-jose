/// <reference types="node" />
import CryptoSuite from '../../lib/interfaces/CryptoSuite';
import { TestPublicKey } from './TestPublicKey';
/**
 * A {@link CryptoSuite} used for unit testing
 */
export default class TestCryptoSuite implements CryptoSuite {
    private readonly id;
    private static called;
    private static readonly ENCRYPT;
    private static readonly DECRYPT;
    private static readonly SIGN;
    private static readonly VERIFY;
    private static readonly SYMENCRYPT;
    private static readonly SYMDECRYPT;
    getKeyConstructors(): {
        test: () => TestPublicKey;
    };
    constructor();
    private encrypt;
    private decrypt;
    private sign;
    private verify;
    private symEncrypt;
    private symDecrypt;
    /** Encryption algorithms */
    getEncrypters(): {
        test: {
            encrypt: (data: Buffer, key: object) => Promise<Buffer>;
            decrypt: (data: Buffer, key: object) => Promise<Buffer>;
        };
    };
    /** Signing algorithms */
    getSigners(): {
        test: {
            sign: ({}: {}, {}: {}) => Promise<string>;
            verify: ({}: {}, {}: {}, {}: {}) => Promise<boolean>;
        };
    };
    getSymmetricEncrypters(): {
        test: {
            encrypt: (plaintext: Buffer, _: Buffer) => Promise<{
                ciphertext: Buffer;
                initializationVector: Buffer;
                key: Buffer;
                tag: Buffer;
            }>;
            decrypt: (ciphertext: Buffer, additionalAuthenticatedData: Buffer, initializationVector: Buffer, key: Buffer, tag: Buffer) => Promise<Buffer>;
        };
    };
    /**
     * Returns true when encrypt() was called since last reset()
     */
    wasEncryptCalled(): boolean;
    /**
     * Returns true when decrypt() was called since last reset()
     */
    wasDecryptCalled(): boolean;
    /**
     * Returns true when sign() was called since last reset()
     */
    wasSignCalled(): boolean;
    /**
     * Returns true when verify() was called since last reset()
     */
    wasVerifyCalled(): boolean;
    /**
     * Returns true when Symmetric Encrypt was called since last reset()
     */
    wasSymEncryptCalled(): boolean;
    /**
     * Returns true when Symmetric Decrypt was called since last reset()
     */
    wasSymDecryptCalled(): boolean;
    /**
     * Resets visited flags for encrypt, decrypt, sign, and verify
     */
    reset(): void;
}
