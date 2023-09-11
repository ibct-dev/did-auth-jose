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
const KeyStoreMem_1 = __importDefault(require("../../lib/keyStore/KeyStoreMem"));
const ProtectionFormat_1 = require("../../lib/keyStore/ProtectionFormat");
const EcPrivateKey_1 = __importDefault(require("../../lib/crypto/ec/EcPrivateKey"));
const Secp256k1CryptoSuite_1 = require("../../lib/crypto/ec/Secp256k1CryptoSuite");
const RsaPrivateKey_1 = __importDefault(require("../../lib/crypto/rsa/RsaPrivateKey"));
const RsaCryptoSuite_1 = require("../../lib/crypto/rsa/RsaCryptoSuite");
const lib_1 = require("../../lib");
const PublicKey_1 = require("../../lib/security/PublicKey");
describe('KeyStoreMem', () => {
    const cryptoFactory = new lib_1.CryptoFactory([new RsaCryptoSuite_1.RsaCryptoSuite(), new Secp256k1CryptoSuite_1.Secp256k1CryptoSuite()]);
    it('should create a new EC signature', (done) => __awaiter(void 0, void 0, void 0, function* () {
        const jwk = yield EcPrivateKey_1.default.generatePrivateKey('key1');
        // Setup registration environment
        const keyStore = new KeyStoreMem_1.default();
        yield keyStore.save('key', jwk);
        const ecKey = yield keyStore.get('key', false);
        expect(ecKey.kty).toBe('EC');
        expect(ecKey.d).toEqual(jwk.d);
        // Get public key
        const ecPublic = yield keyStore.get('key', true);
        expect(ecPublic.kty).toBe('EC');
        expect(ecPublic.d).toBeUndefined();
        // Check signature
        const signature = yield keyStore.sign('key', 'abc', ProtectionFormat_1.ProtectionFormat.FlatJsonJws, cryptoFactory);
        expect(signature).toBeDefined();
        done();
    }));
    it('should create a new RSA signature', (done) => __awaiter(void 0, void 0, void 0, function* () {
        const jwk = yield RsaPrivateKey_1.default.generatePrivateKey('key1');
        // Setup registration environment
        const keyStore = new KeyStoreMem_1.default();
        yield keyStore.save('key', jwk);
        const signature = yield keyStore.sign('key', 'abc', ProtectionFormat_1.ProtectionFormat.FlatJsonJws, cryptoFactory);
        expect(signature).toBeDefined();
        done();
    }));
    it('should list all keys in the store', (done) => __awaiter(void 0, void 0, void 0, function* () {
        const keyStore = new KeyStoreMem_1.default();
        const key1 = {
            kty: PublicKey_1.RecommendedKeyType.Rsa,
            kid: 'kid1',
            e: 'AAEE',
            n: 'xxxxxxxxx',
            defaultEncryptionAlgorithm: 'none'
        };
        const key2 = {
            kty: PublicKey_1.RecommendedKeyType.Rsa,
            kid: 'kid2',
            e: 'AAEE',
            n: 'xxxxxxxxx',
            defaultEncryptionAlgorithm: 'none'
        };
        yield keyStore.save('1', key1);
        yield keyStore.save('2', key2);
        let list = yield keyStore.list();
        expect(list['1']).toBe('kid1');
        expect(list['2']).toBe('kid2');
        done();
    }));
    it('should throw because signing key is not found in store', (done) => __awaiter(void 0, void 0, void 0, function* () {
        // Setup registration environment
        const keyStore = new KeyStoreMem_1.default();
        let throwCaught = false;
        const signature = yield keyStore.sign('key', 'abc', ProtectionFormat_1.ProtectionFormat.FlatJsonJws, cryptoFactory)
            .catch(() => {
            throwCaught = true;
        });
        expect(signature).toBeUndefined();
        expect(throwCaught).toBe(true);
        done();
    }));
    it('should throw because decryption key is not found in store', (done) => __awaiter(void 0, void 0, void 0, function* () {
        // Setup registration environment
        const keyStore = new KeyStoreMem_1.default();
        let throwCaught = false;
        const signature = yield keyStore.decrypt('key', 'abc', ProtectionFormat_1.ProtectionFormat.FlatJsonJwe, cryptoFactory)
            .catch(() => {
            throwCaught = true;
        });
        expect(signature).toBeUndefined();
        expect(throwCaught).toBe(true);
        done();
    }));
    it('should throw because an oct key does not have a public key', (done) => __awaiter(void 0, void 0, void 0, function* () {
        // Setup registration environment
        const jwk = {
            kty: 'oct',
            use: 'sig',
            k: 'AAEE'
        };
        const keyStore = new KeyStoreMem_1.default();
        yield keyStore.save('key', jwk);
        let throwCaught = false;
        const signature = yield keyStore.get('key', true)
            .catch((err) => {
            throwCaught = true;
            expect(err.message).toBe('A secret does not has a public key');
        });
        expect(signature).toBeUndefined();
        expect(throwCaught).toBe(true);
        done();
    }));
    it('should throw because format passed is not a signature format', (done) => __awaiter(void 0, void 0, void 0, function* () {
        // Setup registration environment
        const jwk = yield RsaPrivateKey_1.default.generatePrivateKey('key1');
        const keyStore = new KeyStoreMem_1.default();
        yield keyStore.save('key', jwk);
        let throwCaught = false;
        const signature = yield keyStore.sign('key', 'abc', ProtectionFormat_1.ProtectionFormat.CompactJsonJwe, cryptoFactory)
            .catch((err) => {
            throwCaught = true;
            expect(err.message).toBe('Non signature format passed: 2');
        });
        expect(signature).toBeUndefined();
        expect(throwCaught).toBe(true);
        done();
    }));
    it('should throw because format passed is not an encryption format', (done) => __awaiter(void 0, void 0, void 0, function* () {
        // Setup registration environment
        const jwk = yield RsaPrivateKey_1.default.generatePrivateKey('key1');
        const keyStore = new KeyStoreMem_1.default();
        yield keyStore.save('key', jwk);
        let throwCaught = false;
        const signature = yield keyStore.decrypt('key', 'abc', ProtectionFormat_1.ProtectionFormat.CompactJsonJws, cryptoFactory)
            .catch((err) => {
            throwCaught = true;
            expect(err.message).toBe('Only CompactJsonJwe, FlatJsonJwe is supported by decryption');
        });
        expect(signature).toBeUndefined();
        expect(throwCaught).toBe(true);
        done();
    }));
    it('should throw because key type is not supported', (done) => __awaiter(void 0, void 0, void 0, function* () {
        // Setup registration environment
        const keyStore = new KeyStoreMem_1.default();
        const jwk = {
            kid: 'key1',
            use: 'sig',
            kty: 'oct',
            k: 'AAEE'
        };
        yield keyStore.save('key', jwk);
        let throwCaught = false;
        const signature = yield keyStore.sign('key', 'abc', ProtectionFormat_1.ProtectionFormat.FlatJsonJws, cryptoFactory)
            .catch(() => {
            throwCaught = true;
        });
        expect(signature).toBeUndefined();
        expect(throwCaught).toBe(true);
        done();
    }));
});
//# sourceMappingURL=KeyStoreMem.spec.js.map