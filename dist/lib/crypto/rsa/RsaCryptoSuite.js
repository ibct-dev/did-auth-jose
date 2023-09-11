"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
exports.RsaCryptoSuite = void 0;
const RsaPublicKey_1 = __importDefault(require("./RsaPublicKey"));
// TODO: Create and reference TypeScript definition file for 'jwk-to-pem'
const jwkToPem = require('jwk-to-pem');
const crypto = __importStar(require("crypto"));
const constants = __importStar(require("constants"));
/**
 * Encrypter plugin for RsaSignature2018
 */
class RsaCryptoSuite {
    getSymmetricEncrypters() {
        return {};
    }
    /** Encryption algorithms */
    getEncrypters() {
        return {
            'RSA-OAEP': {
                encrypt: RsaCryptoSuite.encryptRsaOaep,
                decrypt: RsaCryptoSuite.decryptRsaOaep
            }
        };
    }
    /** Signing algorithms */
    getSigners() {
        return {
            RS256: {
                sign: RsaCryptoSuite.signRs256,
                verify: RsaCryptoSuite.verifySignatureRs256
            },
            RS512: {
                sign: RsaCryptoSuite.signRs512,
                verify: RsaCryptoSuite.verifySignatureRs512
            }
        };
    }
    getKeyConstructors() {
        return {
            RsaVerificationKey2018: (keyData) => { return new RsaPublicKey_1.default(keyData); }
        };
    }
    /**
     * Verifies the given signed content using RS256 algorithm.
     *
     * @returns true if passed signature verification, false otherwise.
     */
    static verifySignatureRs256(signedContent, signature, jwk) {
        return new Promise((resolve) => {
            const publicKey = jwkToPem(jwk);
            const verifier = crypto.createVerify('RSA-SHA256');
            verifier.write(signedContent);
            const passedVerification = verifier.verify(publicKey, signature, 'base64');
            resolve(passedVerification);
        });
    }
    /**
     * Sign the given content using the given private key in JWK format using algorithm RS256.
     * TODO: rewrite to get rid of node-jose dependency.
     *
     * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
     * @returns Signed payload in compact JWS format.
     */
    static signRs256(content, jwk) {
        return __awaiter(this, void 0, void 0, function* () {
            const privateKey = jwkToPem(jwk, { private: true });
            const signer = crypto.createSign('RSA-SHA256');
            signer.update(content);
            return signer.sign(privateKey, 'base64');
        });
    }
    /**
     * Verifies the given signed content using RS512 algorithm.
     *
     * @returns true if passed signature verification, false otherwise.
     */
    static verifySignatureRs512(signedContent, signature, jwk) {
        return new Promise((resolve) => {
            const publicKey = jwkToPem(jwk);
            const verifier = crypto.createVerify('RSA-SHA512');
            verifier.write(signedContent);
            const passedVerification = verifier.verify(publicKey, signature, 'base64');
            resolve(passedVerification);
        });
    }
    /**
     * Sign the given content using the given private key in JWK format using algorithm RS512.
     * TODO: rewrite to get rid of node-jose dependency.
     *
     * @param jwsHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the JWS.
     * @returns Signed payload in compact JWS format.
     */
    static signRs512(content, jwk) {
        return __awaiter(this, void 0, void 0, function* () {
            const privateKey = jwkToPem(jwk, { private: true });
            const signer = crypto.createSign('RSA-SHA512');
            signer.update(content);
            return signer.sign(privateKey, 'base64');
        });
    }
    /**
     * Rsa-OAEP encrypts the given data using the given public key in JWK format.
     */
    static encryptRsaOaep(data, jwk) {
        return new Promise((resolve) => {
            const publicKey = jwkToPem(jwk);
            const encryptedDataBuffer = crypto.publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING }, data);
            resolve(encryptedDataBuffer);
        });
    }
    /**
     * Rsa-OAEP decrypts the given data using the given private key in JWK format.
     * TODO: correctly implement this after getting rid of node-jose dependency.
     */
    static decryptRsaOaep(data, jwk) {
        return new Promise((resolve) => {
            const privateKey = jwkToPem(jwk, { private: true });
            const decryptedDataBuffer = crypto.privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING }, data);
            resolve(decryptedDataBuffer);
        });
    }
}
exports.RsaCryptoSuite = RsaCryptoSuite;
//# sourceMappingURL=RsaCryptoSuite.js.map