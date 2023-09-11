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
exports.KeyOperation = exports.RecommendedKeyType = void 0;
const Base64Url_1 = __importDefault(require("../utilities/Base64Url"));
const jose = require('node-jose');
/**
 * JWA recommended KeyTypes to be implemented
 */
var RecommendedKeyType;
(function (RecommendedKeyType) {
    RecommendedKeyType["None"] = "";
    RecommendedKeyType["Ec"] = "EC";
    RecommendedKeyType["Rsa"] = "RSA";
    RecommendedKeyType["Oct"] = "oct";
})(RecommendedKeyType = exports.RecommendedKeyType || (exports.RecommendedKeyType = {}));
/**
 * JWK key operations
 */
var KeyOperation;
(function (KeyOperation) {
    KeyOperation["Sign"] = "sign";
    KeyOperation["Verify"] = "verify";
    KeyOperation["Encrypt"] = "encrypt";
    KeyOperation["Decrypt"] = "decrypt";
    KeyOperation["WrapKey"] = "wrapKey";
    KeyOperation["UnwrapKey"] = "unwrapKey";
    KeyOperation["DeriveKey"] = "deriveKey";
    KeyOperation["DeriveBits"] = "deriveBits";
})(KeyOperation = exports.KeyOperation || (exports.KeyOperation = {}));
/**
 * Represents a Public Key in JWK format.
 * @class
 * @abstract
 * @hideconstructor
 */
class PublicKey {
    constructor() {
        /** Key type */
        this.kty = RecommendedKeyType.None;
        /** Key ID */
        this.kid = '';
        /** Default Encryption Algorithm for JWE 'alg' field */
        this.defaultEncryptionAlgorithm = 'none';
    }
    /**
     * Obtains the thumbprint for the jwk parameter
     * @param jwk JSON object representation of a JWK
     */
    static getThumbprint(publicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = yield jose.JWK.asKey(publicKey);
            const thumbprint = yield key.thumbprint('SHA-512');
            return Base64Url_1.default.encode(thumbprint);
        });
    }
}
exports.default = PublicKey;
//# sourceMappingURL=PublicKey.js.map