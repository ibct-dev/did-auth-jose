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
const EcPublicKey_1 = __importDefault(require("./EcPublicKey"));
const PublicKey_1 = require("../../security/PublicKey");
const ecKey = require('ec-key');
/**
 * Represents an Elliptic Curve private key
 * @class
 * @extends PrivateKey
 */
class EcPrivateKey extends EcPublicKey_1.default {
    /**
     * Constructs a private key given a DID Document public key descriptor containing additional private key
     * information.
     *
     * TODO: This feels odd, should define a separate type.
     *
     * @param key public key object with additional private key information
     */
    constructor(key) {
        super(key);
        /** ECDSA w/ secp256k1 Curve */
        this.defaultSignAlgorithm = 'ES256K';
        let data = key.publicKeyJwk;
        if (!('d' in data)) {
            throw new Error('d required for private elliptic curve key.');
        }
        this.d = data.d;
    }
    /**
     * Wraps a EC private key in jwk format into a Did Document public key object with additonal information
     * @param kid Key ID
     * @param jwk JWK of the private key
     */
    static wrapJwk(kid, jwk) {
        return new EcPrivateKey({
            id: kid,
            type: 'EdDsaSAPublicKeySecp256k1',
            publicKeyJwk: jwk
        });
    }
    /**
     * Generates a new private key
     * @param kid Key ID
     */
    static generatePrivateKey(kid) {
        return __awaiter(this, void 0, void 0, function* () {
            const key = ecKey.createECKey('P-256K');
            // Add the additional JWK parameters
            const jwk = Object.assign(key.toJSON(), {
                kid: kid,
                alg: 'ES256K',
                key_ops: [PublicKey_1.KeyOperation.Sign, PublicKey_1.KeyOperation.Verify]
            });
            return EcPrivateKey.wrapJwk(kid, jwk);
        });
    }
    getPublicKey() {
        return {
            kty: this.kty,
            kid: this.kid,
            crv: this.crv,
            x: this.x,
            y: this.y,
            use: 'verify',
            defaultEncryptionAlgorithm: 'none'
        };
    }
}
exports.default = EcPrivateKey;
//# sourceMappingURL=EcPrivateKey.js.map