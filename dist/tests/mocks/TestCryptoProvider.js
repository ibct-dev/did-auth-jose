"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const TestPublicKey_1 = require("./TestPublicKey");
/**
 * A {@link CryptoSuite} used for unit testing
 */
class TestCryptoSuite {
    constructor() {
        this.id = Math.round(Math.random() * Number.MAX_SAFE_INTEGER);
    }
    getKeyConstructors() {
        return {
            test: () => { return new TestPublicKey_1.TestPublicKey(); }
        };
    }
    encrypt(id) {
        return (data, _) => {
            TestCryptoSuite.called[id] |= TestCryptoSuite.ENCRYPT;
            return Promise.resolve(data);
        };
    }
    decrypt(id) {
        return (data, _) => {
            TestCryptoSuite.called[id] |= TestCryptoSuite.DECRYPT;
            return Promise.resolve(data);
        };
    }
    sign(id) {
        return (_, __) => {
            TestCryptoSuite.called[id] |= TestCryptoSuite.SIGN;
            return Promise.resolve('');
        };
    }
    verify(id) {
        return (_, __, ___) => {
            TestCryptoSuite.called[id] |= TestCryptoSuite.VERIFY;
            return Promise.resolve(true);
        };
    }
    symEncrypt(id) {
        return (plaintext, _) => {
            TestCryptoSuite.called[id] |= TestCryptoSuite.SYMENCRYPT;
            return Promise.resolve({
                ciphertext: plaintext,
                initializationVector: Buffer.alloc(0),
                key: Buffer.alloc(0),
                tag: Buffer.alloc(0)
            });
        };
    }
    symDecrypt(id) {
        return (ciphertext, _, __, ___, ____) => {
            TestCryptoSuite.called[id] |= TestCryptoSuite.SYMDECRYPT;
            return Promise.resolve(ciphertext);
        };
    }
    /** Encryption algorithms */
    getEncrypters() {
        return {
            test: {
                encrypt: this.encrypt(this.id),
                decrypt: this.decrypt(this.id)
            }
        };
    }
    /** Signing algorithms */
    getSigners() {
        return {
            test: {
                sign: this.sign(this.id),
                verify: this.verify(this.id)
            }
        };
    }
    getSymmetricEncrypters() {
        return {
            test: {
                encrypt: this.symEncrypt(this.id),
                decrypt: this.symDecrypt(this.id)
            }
        };
    }
    /**
     * Returns true when encrypt() was called since last reset()
     */
    wasEncryptCalled() {
        return (TestCryptoSuite.called[this.id] & TestCryptoSuite.ENCRYPT) > 0;
    }
    /**
     * Returns true when decrypt() was called since last reset()
     */
    wasDecryptCalled() {
        return (TestCryptoSuite.called[this.id] & TestCryptoSuite.DECRYPT) > 0;
    }
    /**
     * Returns true when sign() was called since last reset()
     */
    wasSignCalled() {
        return (TestCryptoSuite.called[this.id] & TestCryptoSuite.SIGN) > 0;
    }
    /**
     * Returns true when verify() was called since last reset()
     */
    wasVerifyCalled() {
        return (TestCryptoSuite.called[this.id] & TestCryptoSuite.VERIFY) > 0;
    }
    /**
     * Returns true when Symmetric Encrypt was called since last reset()
     */
    wasSymEncryptCalled() {
        return (TestCryptoSuite.called[this.id] & TestCryptoSuite.SYMENCRYPT) > 0;
    }
    /**
     * Returns true when Symmetric Decrypt was called since last reset()
     */
    wasSymDecryptCalled() {
        return (TestCryptoSuite.called[this.id] & TestCryptoSuite.SYMDECRYPT) > 0;
    }
    /**
     * Resets visited flags for encrypt, decrypt, sign, and verify
     */
    reset() {
        TestCryptoSuite.called[this.id] = 0;
    }
}
exports.default = TestCryptoSuite;
TestCryptoSuite.called = {};
TestCryptoSuite.ENCRYPT = 0x1;
TestCryptoSuite.DECRYPT = 0x2;
TestCryptoSuite.SIGN = 0x4;
TestCryptoSuite.VERIFY = 0x8;
TestCryptoSuite.SYMENCRYPT = 0xF;
TestCryptoSuite.SYMDECRYPT = 0x10;
//# sourceMappingURL=TestCryptoProvider.js.map