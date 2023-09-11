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
Object.defineProperty(exports, "__esModule", { value: true });
const PublicKey_1 = __importStar(require("../../security/PublicKey"));
/**
 * Represents an Rsa public key
 * @class
 * @extends PublicKey
 */
class RsaPublicKey extends PublicKey_1.default {
    /**
     * A Rsa JWK
     * @param n The Rsa modulus in Base64urlUInt encoding as specified by RFC7518 6.3.1.1
     * @param e The Rsa public exponent in Base64urlUInt encoding as specified by RFC7518 6.3.1.2
     */
    constructor(keyData) {
        super();
        this.kty = PublicKey_1.RecommendedKeyType.Rsa;
        this.defaultEncryptionAlgorithm = 'RSA-OAEP'; // should be -256
        this.kid = keyData.id;
        const data = keyData;
        if ('publicKeyJwk' in data) {
            const jwk = data.publicKeyJwk;
            if (!keyData.id.endsWith(jwk.kid)) {
                throw new Error(`JWK kid '${jwk.kid}' does not match DID public key id '${keyData.id}'.`);
            }
            if (!jwk.n || !jwk.e) {
                throw new Error('JWK missing required parameters');
            }
            this.n = jwk.n;
            this.e = jwk.e;
        }
        else {
            throw new Error('Cannot parse RsaVerificationKey2018');
        }
    }
}
exports.default = RsaPublicKey;
//# sourceMappingURL=RsaPublicKey.js.map