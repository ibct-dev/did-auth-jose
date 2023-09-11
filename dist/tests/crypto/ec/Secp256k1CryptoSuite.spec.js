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
const Secp256k1CryptoSuite_1 = require("../../../lib/crypto/ec/Secp256k1CryptoSuite");
describe('Secp256k1CryptoSuite', () => __awaiter(void 0, void 0, void 0, function* () {
    it('it should return empty encryptors', () => __awaiter(void 0, void 0, void 0, function* () {
        const cryptoSuite = new Secp256k1CryptoSuite_1.Secp256k1CryptoSuite();
        const encrypters = cryptoSuite.getEncrypters();
        expect(encrypters).toBeDefined();
        expect(encrypters.length).toBeUndefined();
    }));
    it('it should return expected signers', () => __awaiter(void 0, void 0, void 0, function* () {
        const cryptoSuite = new Secp256k1CryptoSuite_1.Secp256k1CryptoSuite();
        const signers = cryptoSuite.getSigners();
        expect(signers).toBeDefined();
        expect(signers['ES256K']).toBeDefined();
        expect(signers['ES256K']['sign']).toEqual(Secp256k1CryptoSuite_1.Secp256k1CryptoSuite.sign);
        expect(signers['ES256K']['verify']).toEqual(Secp256k1CryptoSuite_1.Secp256k1CryptoSuite.verify);
    }));
    it('it should return expected KeyConstructors and subsequent key for Secp256k1VerificationKey2018', () => __awaiter(void 0, void 0, void 0, function* () {
        const cryptoSuite = new Secp256k1CryptoSuite_1.Secp256k1CryptoSuite();
        const keyConstructors = cryptoSuite.getKeyConstructors();
        expect(keyConstructors).toBeDefined();
        expect(keyConstructors['Secp256k1VerificationKey2018']).toBeDefined();
        const keyData = {
            id: 'key-1',
            type: 'Secp256k1VerificationKey2018',
            publicKeyJwk: {
                kid: 'key-1',
                x: 'skdjc4398ru',
                y: 'skdjc4398ru',
                crv: 'P-256K'
            }
        };
        const keyConstructor = keyConstructors['Secp256k1VerificationKey2018'];
        const key = keyConstructor(keyData);
        expect(key).toBeDefined();
    }));
    it('it should return expected KeyConstructors and subsequent key for EdDsaSAPublicKeySecp256k1', () => __awaiter(void 0, void 0, void 0, function* () {
        const cryptoSuite = new Secp256k1CryptoSuite_1.Secp256k1CryptoSuite();
        const keyConstructors = cryptoSuite.getKeyConstructors();
        expect(keyConstructors).toBeDefined();
        expect(keyConstructors['EdDsaSAPublicKeySecp256k1']).toBeDefined();
        const keyData = {
            id: 'key-1',
            type: 'EdDsaSAPublicKeySecp256k1',
            publicKeyJwk: {
                kid: 'key-1',
                x: 'skdjc4398ru',
                y: 'skdjc4398ru',
                crv: 'P-256K'
            }
        };
        const keyConstructor = keyConstructors['EdDsaSAPublicKeySecp256k1'];
        const key = keyConstructor(keyData);
        expect(key).toBeDefined();
    }));
    it('it should return expected KeyConstructors and subsequent key for EdDsaSASignatureSecp256k1', () => __awaiter(void 0, void 0, void 0, function* () {
        const cryptoSuite = new Secp256k1CryptoSuite_1.Secp256k1CryptoSuite();
        const keyConstructors = cryptoSuite.getKeyConstructors();
        expect(keyConstructors).toBeDefined();
        expect(keyConstructors['EdDsaSASignatureSecp256k1']).toBeDefined();
        const keyData = {
            id: 'key-1',
            type: 'EdDsaSASignatureSecp256k1',
            publicKeyJwk: {
                kid: 'key-1',
                x: 'skdjc4398ru',
                y: 'skdjc4398ru',
                crv: 'P-256K'
            }
        };
        const keyConstructor = keyConstructors['EdDsaSASignatureSecp256k1'];
        const key = keyConstructor(keyData);
        expect(key).toBeDefined();
    }));
    it('it should return expected KeyConstructors and subsequent key for EcdsaPublicKeySecp256k1', () => __awaiter(void 0, void 0, void 0, function* () {
        const cryptoSuite = new Secp256k1CryptoSuite_1.Secp256k1CryptoSuite();
        const keyConstructors = cryptoSuite.getKeyConstructors();
        expect(keyConstructors).toBeDefined();
        expect(keyConstructors['EcdsaPublicKeySecp256k1']).toBeDefined();
        const keyData = {
            id: 'key-1',
            type: 'EcdsaPublicKeySecp256k1',
            publicKeyJwk: {
                kid: 'key-1',
                x: 'skdjc4398ru',
                y: 'skdjc4398ru',
                crv: 'P-256K'
            }
        };
        const keyConstructor = keyConstructors['EcdsaPublicKeySecp256k1'];
        const key = keyConstructor(keyData);
        expect(key).toBeDefined();
    }));
    it('it should sign content and verify', () => __awaiter(void 0, void 0, void 0, function* () {
        const ecKey = yield EcPrivateKey_1.default.generatePrivateKey('key-1');
        const signature = yield Secp256k1CryptoSuite_1.Secp256k1CryptoSuite.sign('{ test: "test"}', ecKey);
        expect(signature).toBeDefined();
        const verify = yield Secp256k1CryptoSuite_1.Secp256k1CryptoSuite.verify('{ test: "test"}', signature, ecKey.getPublicKey());
        expect(verify).toBeTruthy();
    }));
    it('it should sign content and fail verification when content altered', () => __awaiter(void 0, void 0, void 0, function* () {
        const ecKey = yield EcPrivateKey_1.default.generatePrivateKey('key-1');
        const signature = yield Secp256k1CryptoSuite_1.Secp256k1CryptoSuite.sign('{ test: "test"}', ecKey);
        expect(signature).toBeDefined();
        const verify = yield Secp256k1CryptoSuite_1.Secp256k1CryptoSuite.verify('{ test: "test_altered"}', signature, ecKey.getPublicKey());
        expect(verify).toBeFalsy();
    }));
    it('it should sign content and fail verification when signature altered', () => __awaiter(void 0, void 0, void 0, function* () {
        const ecKey = yield EcPrivateKey_1.default.generatePrivateKey('key-1');
        const signature = yield Secp256k1CryptoSuite_1.Secp256k1CryptoSuite.sign('{ test: "test"}', ecKey);
        expect(signature).toBeDefined();
        const alteredSignature = signature.substring(0, signature.length - 5); // Trim the signature to break it
        const verify = yield Secp256k1CryptoSuite_1.Secp256k1CryptoSuite.verify('{ test: "test"}', alteredSignature, ecKey.getPublicKey());
        expect(verify).toBeFalsy();
    }));
}));
//# sourceMappingURL=Secp256k1CryptoSuite.spec.js.map