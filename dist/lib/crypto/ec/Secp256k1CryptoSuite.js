"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Secp256k1CryptoSuite = void 0;
const EcPublicKey_1 = __importDefault(require("./EcPublicKey"));
const ecKey = require('ec-key');
/**
 * Encrypter plugin for Elliptic Curve P-256K1
 */
class Secp256k1CryptoSuite {
    getSymmetricEncrypters() {
        return {};
    }
    /** Encryption with Secp256k1 keys not supported */
    getEncrypters() {
        return {};
    }
    /** Signing algorithms */
    getSigners() {
        return {
            ES256K: {
                sign: Secp256k1CryptoSuite.sign,
                verify: Secp256k1CryptoSuite.verify
            }
        };
    }
    /**
     * Defines constructors for the identifiers proposed in Linked Data Cryptographic Suite Registry
     * https://w3c-ccg.github.io/ld-cryptosuite-registry/#eddsasasignaturesecp256k1 plus the additional
     * ones spotted in the wild.
     */
    getKeyConstructors() {
        return {
            Secp256k1VerificationKey2018: (keyData) => { return new EcPublicKey_1.default(keyData); },
            EdDsaSAPublicKeySecp256k1: (keyData) => { return new EcPublicKey_1.default(keyData); },
            EdDsaSASignatureSecp256k1: (keyData) => { return new EcPublicKey_1.default(keyData); },
            EcdsaPublicKeySecp256k1: (keyData) => { return new EcPublicKey_1.default(keyData); }
        };
    }
    /**
     * Verifies the given signed content using SHA256 algorithm.
     *
     * @returns true if passed signature verification, false otherwise.
     */
    static verify(signedContent, signature, jwk) {
        return __awaiter(this, void 0, void 0, function* () {
            const publicKey = new ecKey(jwk);
            const passedVerification = publicKey.createVerify('SHA256')
                .update(signedContent)
                .verify(signature, 'base64');
            return passedVerification;
        });
    }
    /**
     * Sign the given content using the given private key in JWK format using algorithm SHA256.
     *
     * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
     * @returns Signed payload in compact JWS format.
     */
    static sign(content, jwk) {
        return __awaiter(this, void 0, void 0, function* () {
            const privateKey = new ecKey(jwk);
            return privateKey.createSign('SHA256')
                .update(content)
                .sign('base64');
        });
    }
}
exports.Secp256k1CryptoSuite = Secp256k1CryptoSuite;
//# sourceMappingURL=Secp256k1CryptoSuite.js.map