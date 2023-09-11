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
const JwsToken_1 = __importDefault(require("../security/JwsToken"));
const ProtectionFormat_1 = require("./ProtectionFormat");
/**
 * Class to model protection mechanisms
 */
class Protect {
    /**
     * Sign the payload
     * @param keyStorageReference used to reference the signing key
     * @param payload to sign
     * @param format Signature format
     * @param keyStore where to retrieve the signing key
     * @param cryptoFactory used to specify the algorithms to use
     * @param tokenHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.
     */
    static sign(keyStorageReference, payload, format, keyStore, cryptoFactory, tokenHeaderParameters) {
        return __awaiter(this, void 0, void 0, function* () {
            const token = new JwsToken_1.default(payload, cryptoFactory);
            // Get the key
            const jwk = yield keyStore.get(keyStorageReference, false)
                .catch((err) => {
                throw new Error(`The key referenced by '${keyStorageReference}' is not available: '${err}'`);
            });
            switch (jwk.kty.toUpperCase()) {
                case 'RSA':
                    jwk.defaultSignAlgorithm = 'RS256';
                    break;
                case 'EC':
                    jwk.defaultSignAlgorithm = 'ES256K';
                    break;
                default:
                    throw new Error(`The key type '${jwk.kty}' is not supported.`);
            }
            switch (format) {
                case ProtectionFormat_1.ProtectionFormat.CompactJsonJws:
                    return token.sign(jwk, tokenHeaderParameters);
                case ProtectionFormat_1.ProtectionFormat.FlatJsonJws:
                    const flatSignature = yield token.signAsFlattenedJson(jwk, tokenHeaderParameters);
                    return JSON.stringify(flatSignature);
                default:
                    throw new Error(`Non signature format passed: ${format.toString()}`);
            }
        });
    }
    /**
     * Decrypt the data with the key referenced by keyReference.
     * @param keyStorageReference Reference to the key used for signature.
     * @param cipher Data to decrypt
     * @param format Protection format used to decrypt the data
     * @param keyStore where to retrieve the signing key
     * @param cryptoFactory used to specify the algorithms to use
     * @returns The plain text message
     */
    static decrypt(keyStorageReference, cipher, format, keyStore, cryptoFactory) {
        return __awaiter(this, void 0, void 0, function* () {
            if (format !== ProtectionFormat_1.ProtectionFormat.CompactJsonJwe && format !== ProtectionFormat_1.ProtectionFormat.FlatJsonJwe) {
                throw new Error(`Only CompactJsonJwe, FlatJsonJwe is supported by decryption`);
            }
            // Get the key
            const jwk = yield keyStore.get(keyStorageReference, false)
                .catch((err) => {
                throw new Error(`The key referenced by '${keyStorageReference}' is not available: '${err}'`);
            });
            const jweToken = cryptoFactory.constructJwe(cipher);
            const payload = yield jweToken.decrypt(jwk);
            return payload;
        });
    }
}
exports.default = Protect;
//# sourceMappingURL=Protect.js.map