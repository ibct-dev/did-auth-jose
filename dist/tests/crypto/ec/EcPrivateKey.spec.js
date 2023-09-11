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
const EcPrivateKey_1 = __importDefault(require("../../../lib/crypto/ec/EcPrivateKey"));
const PublicKey_1 = require("../../../lib/security/PublicKey");
describe('EcPrivateKey', () => __awaiter(void 0, void 0, void 0, function* () {
    it('constructor should throw when no jwk.d', () => __awaiter(void 0, void 0, void 0, function* () {
        const key = {
            id: 'key-1',
            type: 'EdDsaSAPublicKeySecp256k1',
            controller: 'did:example:controller.id',
            publicKeyJwk: {
                kid: 'key-1',
                x: 'skdjc4398ru',
                y: 'skdjc4398ru',
                crv: 'P-256K'
            }
        };
        expect(() => new EcPrivateKey_1.default(key)).toThrowError('d required for private elliptic curve key.');
    }));
    it('it should create a private key', () => __awaiter(void 0, void 0, void 0, function* () {
        const ecKey = yield EcPrivateKey_1.default.generatePrivateKey('key-1');
        expect(ecKey).toBeDefined();
        expect(ecKey.kty).toEqual('EC');
        expect(ecKey.kid).toEqual('key-1');
        expect(ecKey.key_ops).toEqual([PublicKey_1.KeyOperation.Sign, PublicKey_1.KeyOperation.Verify]);
        expect(ecKey.defaultEncryptionAlgorithm).toEqual('none');
        expect(ecKey.crv).toEqual('P-256K');
        expect(ecKey.defaultSignAlgorithm).toEqual('ES256K');
        expect(ecKey.d).toBeDefined();
        expect(ecKey.x).toBeDefined();
        expect(ecKey.y).toBeDefined();
    }));
}));
//# sourceMappingURL=EcPrivateKey.spec.js.map