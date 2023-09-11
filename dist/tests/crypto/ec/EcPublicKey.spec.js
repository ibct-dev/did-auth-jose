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
const EcPublicKey_1 = __importDefault(require("../../../lib/crypto/ec/EcPublicKey"));
describe('EcPublicKey', () => __awaiter(void 0, void 0, void 0, function* () {
    it('constructor should throw when no publicKeyJwk', () => __awaiter(void 0, void 0, void 0, function* () {
        const key = {
            id: 'key-1',
            type: 'Secp256k1VerificationKey2018',
            controller: 'did:example:controller.id'
        };
        expect(() => new EcPublicKey_1.default(key)).toThrowError('Cannot parse Elliptic Curve key.');
    }));
    it('constructor should throw when no kid\'s do not match', () => __awaiter(void 0, void 0, void 0, function* () {
        const key = {
            id: 'key-1',
            type: 'Secp256k1VerificationKey2018',
            controller: 'did:example:controller.id',
            publicKeyJwk: {
                kid: 'key-2',
                x: 'skdjc4398ru',
                y: 'skdjc4398ru',
                crv: 'P-256K'
            }
        };
        expect(() => new EcPublicKey_1.default(key)).toThrowError('JWK kid does not match Did publickey id.');
    }));
    it('constructor should throw when missing x from jwk', () => __awaiter(void 0, void 0, void 0, function* () {
        const key = {
            id: 'key-1',
            type: 'Secp256k1VerificationKey2018',
            controller: 'did:example:controller.id',
            publicKeyJwk: {
                kid: 'key-1',
                y: 'skdjc4398ru',
                crv: 'P-256K'
            }
        };
        expect(() => new EcPublicKey_1.default(key)).toThrowError('JWK missing required parameters.');
    }));
    it('constructor should throw when missing y from jwk', () => __awaiter(void 0, void 0, void 0, function* () {
        const key = {
            id: 'key-1',
            type: 'Secp256k1VerificationKey2018',
            controller: 'did:example:controller.id',
            publicKeyJwk: {
                kid: 'key-1',
                x: 'skdjc4398ru',
                crv: 'P-256K'
            }
        };
        expect(() => new EcPublicKey_1.default(key)).toThrowError('JWK missing required parameters.');
    }));
    it('constructor should throw when missing crv from jwk', () => __awaiter(void 0, void 0, void 0, function* () {
        const key = {
            id: 'key-1',
            type: 'Secp256k1VerificationKey2018',
            controller: 'did:example:controller.id',
            publicKeyJwk: {
                kid: 'key-1',
                x: 'skdjc4398ru',
                y: 'skdjc4398ru'
            }
        };
        expect(() => new EcPublicKey_1.default(key)).toThrowError('JWK missing required parameters.');
    }));
}));
//# sourceMappingURL=EcPublicKey.spec.js.map