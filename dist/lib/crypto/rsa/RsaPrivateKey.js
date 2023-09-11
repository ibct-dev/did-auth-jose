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
const RsaPublicKey_1 = __importDefault(require("./RsaPublicKey"));
const jose = require('node-jose');
const keystore = jose.JWK.createKeyStore();
/**
 * Represents an Rsa private key
 * @class
 * @extends PrivateKey
 */
class RsaPrivateKey extends RsaPublicKey_1.default {
    /**
     * Constructs a private key given a Did Document public key object containing additional private key
     * information
     * @param key public key object with additional private key information
     */
    constructor(key) {
        super(key);
        this.defaultSignAlgorithm = 'RS256';
        if (!('publicKeyJwk' in key)) {
            throw new Error('publicKeyJwk must exist on IDidDocumentPublicKey');
        }
        let data = key.publicKeyJwk;
        if (!('d' in data)) {
            throw new Error('d required for private rsa key');
        }
        this.d = data.d;
        this.p = data.p;
        this.q = data.q;
        this.dp = data.dp;
        this.dq = data.dq;
        this.qi = data.qi;
        this.oth = data.oth;
    }
    /**
     * Wraps a rsa private key in jwk format into a Did Document public key object with additonal information
     * @param kid Key ID
     * @param jwk JWK of the private key
     */
    static wrapJwk(kid, jwk) {
        return new RsaPrivateKey({
            id: kid,
            type: 'RsaVerificationKey2018',
            publicKeyJwk: jwk
        });
    }
    /**
     * Generates a new private key
     * @param kid Key ID
     */
    static generatePrivateKey(kid) {
        return __awaiter(this, void 0, void 0, function* () {
            const additionalProperties = {
                defaultEncryptionAlgorithm: 'RSA-OAEP',
                defaultSignAlgorithm: 'RS256',
                kid: kid
            };
            const keygen = yield keystore.generate('RSA', 512, additionalProperties);
            return RsaPrivateKey.wrapJwk(kid, keygen.toJSON(true));
        });
    }
    getPublicKey() {
        return {
            kty: this.kty,
            kid: this.kid,
            e: this.e,
            n: this.n,
            defaultEncryptionAlgorithm: this.defaultEncryptionAlgorithm
        };
    }
}
exports.default = RsaPrivateKey;
//# sourceMappingURL=RsaPrivateKey.js.map