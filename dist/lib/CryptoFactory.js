"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const JweToken_1 = __importDefault(require("./security/JweToken"));
const JwsToken_1 = __importDefault(require("./security/JwsToken"));
/**
 * Utility class to handle all CryptoSuite dependency injection
 */
class CryptoFactory {
    /**
     * Constructs a new CryptoRegistry
     * @param suites The suites to use for dependency injeciton
     */
    constructor(suites, defaultSymmetricAlgorithm) {
        this.encrypters = {};
        this.symmetricEncrypters = {};
        this.signers = {};
        this.keyConstructors = {};
        this.defaultSymmetricAlgorithm = 'none';
        // takes each suite (CryptoSuite objects) and maps to name of the algorithm.
        suites.forEach((suite) => {
            const encAlgorithms = suite.getEncrypters();
            for (const encrypterKey in encAlgorithms) {
                this.encrypters[encrypterKey] = encAlgorithms[encrypterKey];
            }
            const symEncAlgorithms = suite.getSymmetricEncrypters();
            for (const encrypterKey in symEncAlgorithms) {
                this.symmetricEncrypters[encrypterKey] = symEncAlgorithms[encrypterKey];
            }
            const signerAlgorithms = suite.getSigners();
            for (const signerKey in signerAlgorithms) {
                this.signers[signerKey] = signerAlgorithms[signerKey];
            }
            const pluginKeyConstructors = suite.getKeyConstructors();
            for (const keyType in pluginKeyConstructors) {
                this.keyConstructors[keyType] = pluginKeyConstructors[keyType];
            }
        });
        if (defaultSymmetricAlgorithm) {
            this.defaultSymmetricAlgorithm = defaultSymmetricAlgorithm;
        }
        else {
            for (const algorithm in this.symmetricEncrypters) {
                this.defaultSymmetricAlgorithm = algorithm;
                break;
            }
        }
    }
    /**
     * constructs the jwe to be encrypted or decrypted
     * @param content content for the JWE
     */
    constructJwe(content) {
        return new JweToken_1.default(content, this);
    }
    /**
     * constructs the jws to be signed or verified
     * @param content content for the JWS
     */
    constructJws(content) {
        return new JwsToken_1.default(content, this);
    }
    /**
     * Given a public key definition from a DID Document, constructs a JWK public key. Throws an error
     * if the key definition cannot be converted.
     *
     * @param key publicKey object from a {@link DidDocument}
     * @returns The same key as a {@link PublicKey}
     */
    constructPublicKey(publicKey) {
        return this.keyConstructors[publicKey.type](publicKey);
    }
    /**
     * Gets the Encrypter object given the encryption algorithm's name
     * @param name The name of the algorithm
     * @returns The corresponding Encrypter, if any
     */
    getEncrypter(name) {
        return this.encrypters[name];
    }
    /**
     * Gets the Signer object given the signing algorithm's name
     * @param name The name of the algorithm
     * @returns The corresponding Signer, if any
     */
    getSigner(name) {
        return this.signers[name];
    }
    /**
     * Gets the SymmetricEncrypter object given the symmetric encryption algorithm's name
     * @param name The name of the algorithm
     * @returns The corresponding SymmetricEncrypter, if any
     */
    getSymmetricEncrypter(name) {
        return this.symmetricEncrypters[name];
    }
    /**
     * Gets the default symmetric encryption algorithm to use
     */
    getDefaultSymmetricEncryptionAlgorithm() {
        return this.defaultSymmetricAlgorithm;
    }
}
exports.default = CryptoFactory;
//# sourceMappingURL=CryptoFactory.js.map