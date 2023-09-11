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
 * Represents an Elliptic Curve public key
 * @class
 * @extends PublicKey
 */
class EcPublicKey extends PublicKey_1.default {
    /**
     * An Elliptic Curve JWK
     * @param keyData The IDidDocumentPublicKey containing the elliptic curve public key parameters.
     */
    constructor(keyData) {
        super();
        this.kty = PublicKey_1.RecommendedKeyType.Ec;
        this.kid = keyData.id;
        const data = keyData;
        if ('publicKeyJwk' in data) {
            const jwk = data.publicKeyJwk;
            if (!keyData.id.endsWith(jwk.kid)) {
                throw new Error('JWK kid does not match Did publickey id.');
            }
            if (!jwk.crv || !jwk.x || !jwk.y) {
                throw new Error('JWK missing required parameters.');
            }
            this.crv = jwk.crv;
            this.x = jwk.x;
            this.y = jwk.y;
            this.key_ops = jwk.key_ops;
            this.use = this.use;
        }
        else {
            throw new Error('Cannot parse Elliptic Curve key.');
        }
    }
}
exports.default = EcPublicKey;
//# sourceMappingURL=EcPublicKey.js.map