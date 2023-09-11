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
const JwsToken_1 = __importDefault(require("../../lib/security/JwsToken"));
const TestCryptoProvider_1 = __importDefault(require("../mocks/TestCryptoProvider"));
const Base64Url_1 = __importDefault(require("../../lib/utilities/Base64Url"));
const TestPublicKey_1 = require("../mocks/TestPublicKey");
const CryptoFactory_1 = __importDefault(require("../../lib/CryptoFactory"));
const TestPrivateKey_1 = __importDefault(require("../mocks/TestPrivateKey"));
const lib_1 = require("../../lib");
describe('JwsToken', () => {
    const crypto = new TestCryptoProvider_1.default();
    let registry;
    beforeEach(() => {
        registry = new CryptoFactory_1.default([crypto]);
    });
    describe('constructor', () => {
        it('should construct from a flattened JSON object', () => {
            const correctJWS = {
                protected: 'foo',
                payload: 'foobar',
                signature: 'baz'
            };
            const jws = new JwsToken_1.default(correctJWS, registry);
            expect(jws['protectedHeaders']).toEqual('foo');
            expect(jws['payload']).toEqual('foobar');
            expect(jws['signature']).toEqual('baz');
            expect(jws['unprotectedHeaders']).toBeUndefined();
        });
        it('should construct from a flattened JSON object using header', () => {
            const correctJWS = {
                header: {
                    alg: 'test',
                    kid: 'test'
                },
                payload: 'foobar',
                signature: 'baz'
            };
            const jws = new JwsToken_1.default(correctJWS, registry);
            expect(jws['protectedHeaders']).toBeUndefined();
            expect(jws['unprotectedHeaders']).toBeDefined();
            expect(jws['unprotectedHeaders']['kid']).toEqual('test');
            expect(jws['payload']).toEqual('foobar');
            expect(jws['signature']).toEqual('baz');
        });
        it('should include nonprotected headers', () => {
            const correctJWS = {
                protected: 'foo',
                header: {
                    foo: 'bar'
                },
                payload: 'foobar',
                signature: 'baz'
            };
            const jws = new JwsToken_1.default(correctJWS, registry);
            expect(jws['protectedHeaders']).toEqual('foo');
            expect(jws['payload']).toEqual('foobar');
            expect(jws['signature']).toEqual('baz');
            expect(jws['unprotectedHeaders']).toBeDefined();
            expect(jws['unprotectedHeaders']['foo']).toEqual('bar');
        });
        it('should ignore objects with invalid header formats', () => {
            const correctJWS = {
                header: 'wrong',
                payload: 'foobar',
                signature: 'baz'
            };
            const jws = new JwsToken_1.default(correctJWS, registry);
            expect(jws['protectedHeaders']).toBeUndefined();
        });
        it('should ignore objects missing protected and header', () => {
            const correctJWS = {
                payload: 'foobar',
                signature: 'baz'
            };
            const jws = new JwsToken_1.default(correctJWS, registry);
            expect(jws['protectedHeaders']).toBeUndefined();
        });
        it('should ignore objects missing signature', () => {
            const correctJWS = {
                protected: 'foo',
                payload: 'foobar'
            };
            const jws = new JwsToken_1.default(correctJWS, registry);
            expect(jws['protectedHeaders']).toBeUndefined();
        });
        it('should parse a JSON JWS from a string', () => __awaiter(void 0, void 0, void 0, function* () {
            const testValue = Math.random().toString(16);
            const token = new JwsToken_1.default(testValue, registry);
            const privateKey = new TestPrivateKey_1.default();
            const encryptedToken = yield token.signAsFlattenedJson(privateKey);
            const encryptedTokenAsString = JSON.stringify(encryptedToken);
            const actualToken = new JwsToken_1.default(encryptedTokenAsString, registry);
            expect(actualToken.isContentWellFormedToken()).toBeTruthy();
            const actualValue = yield actualToken.verifySignature(privateKey.getPublicKey());
            expect(actualValue).toEqual(testValue);
        }));
    });
    describe('verifySignature', () => {
        const header = {
            alg: 'test',
            kid: 'did:example:123456789abcdefghi#keys-1'
        };
        const payload = {
            description: 'JWSToken test'
        };
        it('should throw an error because algorithm unsupported', () => __awaiter(void 0, void 0, void 0, function* () {
            const unsupportedHeader = {
                alg: 'RS256',
                kid: 'did:example:123456789abcdefghi#keys-1'
            };
            const data = Base64Url_1.default.encode(JSON.stringify(unsupportedHeader)) + '.' +
                Base64Url_1.default.encode(JSON.stringify(payload)) + '.';
            const jwsToken = new JwsToken_1.default(data, registry);
            try {
                yield jwsToken.verifySignature(new TestPublicKey_1.TestPublicKey());
                fail('Expected verifySignature to throw');
            }
            catch (err) {
                expect(err.message).toContain('Unsupported signing algorithm');
            }
        }));
        it('should throw an error because signature failed', () => __awaiter(void 0, void 0, void 0, function* () {
            const data = Base64Url_1.default.encode(JSON.stringify(header)) + '.' +
                Base64Url_1.default.encode(JSON.stringify(payload)) + '.';
            spyOn(crypto, 'getSigners').and.returnValue({
                test: {
                    sign: () => { return Buffer.from(''); },
                    verify: (_, __, ___) => { return Promise.resolve(false); }
                }
            });
            registry = new CryptoFactory_1.default([crypto]);
            const jwsToken = new JwsToken_1.default(data, registry);
            try {
                yield jwsToken.verifySignature(new TestPublicKey_1.TestPublicKey());
                fail('Expected verifySignature to throw');
            }
            catch (err) {
                expect(err.message).toContain('Failed signature validation');
            }
        }));
        it('should call the crypto Algorithms\'s verify', () => __awaiter(void 0, void 0, void 0, function* () {
            const data = Base64Url_1.default.encode(JSON.stringify(header)) + '.' +
                Base64Url_1.default.encode(JSON.stringify(payload)) + '.';
            const jwsToken = new JwsToken_1.default(data, registry);
            crypto.reset();
            try {
                yield jwsToken.verifySignature(new TestPublicKey_1.TestPublicKey());
            }
            catch (err) {
                // This signature will fail.
            }
            expect(crypto.wasVerifyCalled()).toBeTruthy();
        }));
        it('should require the JWS to have been parsed correctly', () => __awaiter(void 0, void 0, void 0, function* () {
            const jws = new JwsToken_1.default('I am not decryptable', registry);
            try {
                yield jws.verifySignature(new TestPublicKey_1.TestPublicKey());
                fail('expected to throw');
            }
            catch (err) {
                expect(err.message).toContain('Could not parse contents into a JWS');
            }
        }));
    });
    describe('getPayload', () => {
        let data;
        let payload;
        beforeEach(() => {
            data = JSON.stringify({
                test: Math.random()
            });
            payload = Base64Url_1.default.encode(data);
        });
        it('should return the payload from a compact JWS', () => {
            const jws = new JwsToken_1.default(`.${payload}.`, registry);
            expect(jws.getPayload()).toEqual(data);
        });
        it('should return the payload from a Flattened JSON JWS', () => {
            const jws = new JwsToken_1.default({
                header: {
                    alg: 'none'
                },
                payload,
                signature: ''
            }, registry);
            expect(jws.getPayload()).toEqual(data);
        });
        it('should return the original content if it was unable to parse a JWS', () => {
            const jws = new JwsToken_1.default('some test value', registry);
            expect(jws.getPayload()).toEqual('some test value');
        });
    });
    describe('sign', () => {
        const data = {
            description: 'JWSToken test'
        };
        it('should throw an error because the algorithm is not supported', () => __awaiter(void 0, void 0, void 0, function* () {
            const privateKey = new TestPrivateKey_1.default();
            privateKey.defaultSignAlgorithm = 'unsupported';
            const jwsToken = new JwsToken_1.default(data, registry);
            try {
                yield jwsToken.sign(privateKey);
            }
            catch (err) {
                expect(err).toBeDefined();
                return;
            }
            fail('Sign did not throw');
        }));
        it('should call the crypto Algorithms\'s sign', () => __awaiter(void 0, void 0, void 0, function* () {
            const jwsToken = new JwsToken_1.default(data, registry);
            crypto.reset();
            yield jwsToken.sign(new TestPrivateKey_1.default());
            expect(crypto.wasSignCalled()).toBeTruthy();
        }));
        it('should not add its own alg and kid headers if ones are provided', () => __awaiter(void 0, void 0, void 0, function* () {
            const privateKey = new TestPrivateKey_1.default();
            const jwsToken = new JwsToken_1.default(data, registry);
            try {
                yield jwsToken.sign(privateKey, {
                    alg: 'unknown',
                    kid: 'also unknown'
                });
                fail('expected to throw');
            }
            catch (err) {
                expect(err).toBeDefined();
                return;
            }
        }));
    });
    describe('signAsFlattenedJson', () => {
        let data;
        beforeEach(() => {
            data = {
                description: `test: ${Math.random()}`
            };
        });
        it('should throw an error because the algorithm is not supported', () => __awaiter(void 0, void 0, void 0, function* () {
            const privateKey = new TestPrivateKey_1.default();
            privateKey.defaultSignAlgorithm = 'unsupported';
            const jwsToken = new JwsToken_1.default(data, registry);
            try {
                yield jwsToken.signAsFlattenedJson(privateKey);
            }
            catch (err) {
                expect(err).toBeDefined();
                return;
            }
            fail('Sign did not throw');
        }));
        it('should call the crypto Algorithms\'s sign', () => __awaiter(void 0, void 0, void 0, function* () {
            const jwsToken = new JwsToken_1.default(data, registry);
            crypto.reset();
            yield jwsToken.signAsFlattenedJson(new TestPrivateKey_1.default());
            expect(crypto.wasSignCalled()).toBeTruthy();
        }));
        it('should return the expected JSON JWS', () => __awaiter(void 0, void 0, void 0, function* () {
            const jwsToken = new JwsToken_1.default(data, registry);
            const key = new TestPrivateKey_1.default();
            const jws = yield jwsToken.signAsFlattenedJson(key);
            expect(jws.signature).toBeDefined();
            expect(Base64Url_1.default.decode(jws.payload)).toEqual(JSON.stringify(data));
        }));
        it('should not add alg or kid if they are provided in the header', () => __awaiter(void 0, void 0, void 0, function* () {
            const privateKey = new TestPrivateKey_1.default();
            const jwsToken = new JwsToken_1.default(data, registry);
            const jws = yield jwsToken.signAsFlattenedJson(privateKey, {
                header: {
                    alg: privateKey.defaultSignAlgorithm,
                    kid: privateKey.kid
                }
            });
            expect(jws.signature).toBeDefined();
            expect(jws.protected).toBeUndefined();
        }));
    });
    describe('toCompactJws', () => {
        it('should fail if the token is not a JWS', () => {
            const token = new JwsToken_1.default('definately not a jws', registry);
            try {
                token.toCompactJws();
                fail('expected to throw');
            }
            catch (err) {
                expect(err.message).toContain('parse');
            }
        });
        it('should fail if alg is not a protected header', () => {
            const token = new JwsToken_1.default({
                protected: '',
                payload: '',
                signature: ''
            }, registry);
            try {
                token.toCompactJws();
                fail('expected to throw');
            }
            catch (err) {
                expect(err.message).toContain('alg');
            }
        });
        it('should form a compact JWS', () => {
            const expectedProtected = Base64Url_1.default.encode(JSON.stringify({
                alg: 'RSA-OAEP'
            }));
            const token = new JwsToken_1.default({
                protected: expectedProtected,
                header: {
                    test: 'should be ignored'
                },
                payload: 'signedContent',
                signature: 'signature'
            }, registry);
            expect(token.toCompactJws()).toEqual(`${expectedProtected}.signedContent.signature`);
        });
    });
    describe('toFlattenedJsonJws', () => {
        const expectedProtected = Base64Url_1.default.encode(JSON.stringify({
            alg: 'RSA-OAEP'
        }));
        const signature = 'signature';
        const payload = 'signedContent';
        let jws;
        beforeEach(() => {
            jws = `${expectedProtected}.${payload}.${signature}`;
        });
        it('should fail if the token is not a JWS', () => {
            const token = new JwsToken_1.default('not a jws', registry);
            try {
                token.toFlattenedJsonJws();
                fail('expected to throw');
            }
            catch (err) {
                expect(err.message).toContain('parse');
            }
        });
        it('should fail if alg is not a header', () => {
            jws = `.${payload}.${signature}`;
            const token = new JwsToken_1.default(jws, registry);
            try {
                token.toFlattenedJsonJws();
                fail('expected to throw');
            }
            catch (err) {
                expect(err.message).toContain('alg');
            }
        });
        it('should form a JSON JWS from a compact JWS', () => {
            const token = new JwsToken_1.default(jws, registry);
            expect(token.toFlattenedJsonJws()).toEqual({
                protected: expectedProtected,
                payload,
                signature
            });
        });
        it('should override unprotected headers with those passed to it', () => {
            const headers = {
                test: 'foo'
            };
            const token = new JwsToken_1.default({
                protected: expectedProtected,
                header: {
                    test: 'bar'
                },
                payload,
                signature
            }, registry);
            expect(token.toFlattenedJsonJws(headers)).toEqual({
                protected: expectedProtected,
                header: headers,
                payload,
                signature
            });
        });
        it('should accept JWSs with no protected header', () => {
            const headers = {
                alg: 'RSA-OAEP'
            };
            const token = new JwsToken_1.default({
                header: {
                    test: 'bar'
                },
                payload,
                signature
            }, registry);
            expect(token.toFlattenedJsonJws(headers)).toEqual({
                header: headers,
                payload,
                signature
            });
        });
    });
    describe('validations', () => {
        beforeEach(() => {
            registry = new CryptoFactory_1.default([new lib_1.RsaCryptoSuite()]);
        });
        describe('RSASSA-PKCS1-v1_5 SHA-256', () => {
            // rfc-7515 A.2.1
            const headers = { alg: 'RS256' };
            // rfc-7515 A.2.1
            const encodedHeaders = 'eyJhbGciOiJSUzI1NiJ9';
            // rfc-7515 A.2.1
            const payload = Buffer.from([123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
                32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
                48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
                109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
                111, 116, 34, 58, 116, 114, 117, 101, 125]);
            // rfc-7515 A.2.1
            const encodedPayload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt' +
                'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
            // rfc-7515 A.2.1
            const rsaKey = {
                kty: 'RSA',
                n: 'ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx' +
                    'HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs' +
                    'D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH' +
                    'SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV' +
                    'MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8' +
                    'NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ',
                e: 'AQAB',
                d: 'Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I' +
                    'jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0' +
                    'BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn' +
                    '439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT' +
                    'CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh' +
                    'BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ',
                p: '4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi' +
                    'YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG' +
                    'BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc',
                q: 'uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa' +
                    'ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA' +
                    '-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc',
                dp: 'BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q' +
                    'CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb' +
                    '34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0',
                dq: 'h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa' +
                    '7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky' +
                    'NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU',
                qi: 'IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o' +
                    'y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU' +
                    'W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U'
            };
            // rfc-7515 A.2.1
            const finalJws = 'eyJhbGciOiJSUzI1NiJ9' +
                '.' +
                'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt' +
                'cGxlLmNvbS9pc19yb290Ijp0cnVlfQ' +
                '.' +
                'cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7' +
                'AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4' +
                'BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K' +
                '0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv' +
                'hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB' +
                'p0igcN_IoypGlUPQGe77Rw';
            it('signs correctly', () => __awaiter(void 0, void 0, void 0, function* () {
                const jws = new JwsToken_1.default(payload.toString(), registry);
                const privateKey = rsaKey;
                privateKey['defaultSignAlgorithm'] = 'RS256';
                const signed = yield jws.sign(privateKey);
                expect(signed).toEqual(finalJws);
            }));
            it('should validate correctly', () => __awaiter(void 0, void 0, void 0, function* () {
                const jws = new JwsToken_1.default(finalJws, registry);
                expect(jws['protectedHeaders']).toEqual(encodedHeaders);
                expect(jws['payload']).toEqual(encodedPayload);
                expect(jws.getHeader()).toEqual(headers);
                const publicKey = {
                    kty: 'RSA',
                    n: rsaKey.n,
                    e: rsaKey.e
                };
                const actualPayload = yield jws.verifySignature(publicKey);
                expect(actualPayload).toEqual(payload.toString());
            }));
        });
    });
});
//# sourceMappingURL=JwsToken.spec.js.map