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
Object.defineProperty(exports, "__esModule", { value: true });
const did_common_typescript_1 = require("@decentralized-identity/did-common-typescript");
const lib_1 = require("../lib");
const lib_2 = require("../lib");
describe('Authentication', () => {
    let hubkey;
    let examplekey;
    let hubPublicKey;
    let hubResolvedDID;
    let hubKeys = {};
    let examplePublicKey;
    let exampleResolvedDID;
    let auth;
    let registry = new lib_1.CryptoFactory([new lib_1.RsaCryptoSuite(), new lib_1.AesCryptoSuite()]);
    let resolver = new did_common_typescript_1.unitTestExports.TestResolver();
    const hubDID = 'did:example:did';
    const exampleDID = 'did:example:123456789abcdefghi';
    beforeAll((done) => __awaiter(void 0, void 0, void 0, function* () {
        hubkey = yield lib_1.PrivateKeyRsa.generatePrivateKey(`${hubDID}#key1`);
        examplekey = yield lib_1.PrivateKeyRsa.generatePrivateKey(`${exampleDID}#keys-1`);
        hubPublicKey = hubkey.getPublicKey();
        hubKeys = {
            'did:example:did#key1': hubkey
        };
        examplePublicKey = examplekey.getPublicKey();
        exampleResolvedDID = new did_common_typescript_1.DidDocument({
            '@context': 'https://w3id.org/did/v1',
            'id': exampleDID,
            'publicKey': [{
                    id: `${exampleDID}#keys-1`,
                    type: 'RsaVerificationKey2018',
                    controller: exampleDID,
                    publicKeyJwk: examplePublicKey
                }],
            'authentication': [{
                    type: 'RsaSignatureAuthentication2018',
                    publicKey: `${exampleDID}#keys-1`
                }],
            'service': [{
                    id: 'example-service',
                    type: 'ExampleService',
                    serviceEndpoint: 'https://example.com/endpoint/8377464'
                }]
        });
        hubResolvedDID = new did_common_typescript_1.DidDocument({
            '@context': 'https://w3id.org/did/v1',
            'id': hubDID,
            'publicKey': [{
                    id: `${hubDID}#key1`,
                    type: 'RsaVerificationKey2018',
                    controller: hubDID,
                    publicKeyJwk: hubPublicKey
                }]
        });
        auth = new lib_1.Authentication({
            resolver,
            keys: hubKeys
        });
        done();
    }));
    // creates a new access token for 5 minutes using the key given
    function newAccessToken(key = hubkey) {
        return __awaiter(this, void 0, void 0, function* () {
            return registry.constructJws({
                sub: exampleDID,
                iat: new Date(Date.now()),
                exp: new Date(Date.now() + 5 * 60 * 1000)
            }).sign(key);
        });
    }
    // sets the resolver's resolution for a did, clearing all others
    function setResolve(forDid, resolution) {
        resolver.setHandle((did) => {
            return new Promise((resolve, reject) => {
                if (did === forDid) {
                    resolve(resolution);
                }
                else {
                    reject(`Attempted to resolve erroneous did ${did}`);
                }
            });
        });
    }
    let header = {
        'alg': 'RS256',
        'kid': `${exampleDID}#keys-1`,
        'did-access-token': ''
    };
    let authenticationRequest = {
        iss: hubDID,
        response_type: 'id_token',
        client_id: '',
        scope: 'openid',
        state: '',
        nonce: '123456789',
        claims: { id_token: {} }
    };
    beforeEach(() => __awaiter(void 0, void 0, void 0, function* () {
        const token = yield newAccessToken();
        header = {
            'alg': 'RS256',
            'kid': `${exampleDID}#keys-1`,
            'did-access-token': token
        };
        setResolve(exampleDID, exampleResolvedDID);
        authenticationRequest = {
            iss: hubDID,
            response_type: 'id_token',
            client_id: 'https://example.com/endpoint/8377464',
            scope: 'openid',
            state: '',
            nonce: '123456789',
            claims: { id_token: {} }
        };
    }));
    describe('Authentication', () => {
        it('should throw if no keys are passed in', () => {
            let throws = false;
            try {
                // tslint:disable-next-line:no-unused-expression
                new lib_1.Authentication({
                    resolver
                });
            }
            catch (err) {
                throws = true;
                expect(err.message).toEqual(`A key by reference (keyReferences) or a key by value (keys) is required`);
            }
            expect(throws).toBeTruthy();
        });
        it('should throw if mixed keys are passed in', () => {
            let throws = false;
            try {
                // tslint:disable-next-line:no-unused-expression
                new lib_1.Authentication({
                    keys: hubKeys,
                    keyReferences: ['abc'],
                    resolver
                });
            }
            catch (err) {
                throws = true;
                expect(err.message).toEqual(`Do not mix a key by reference (keyReferences) with a key by value (keys) is required`);
            }
            expect(throws).toBeTruthy();
        });
    });
    describe('signAuthenticationRequest', () => {
        it('should throw error when cannot find key for DID', () => __awaiter(void 0, void 0, void 0, function* () {
            authenticationRequest.iss = 'did:test:wrongdid';
            try {
                const context = yield auth.signAuthenticationRequest(authenticationRequest);
                fail('Auth did not throw.');
                console.log(context);
            }
            catch (err) {
                expect(err).toBeDefined();
            }
        }));
        it('should sign the request', () => __awaiter(void 0, void 0, void 0, function* () {
            const request = yield auth.signAuthenticationRequest(authenticationRequest);
            const jws = new lib_1.JwsToken(request, registry);
            const payload = yield jws.verifySignature(hubPublicKey);
            expect(payload).toEqual(JSON.stringify(authenticationRequest));
        }));
    });
    describe('verifyAuthenticationRequest', () => {
        it('should throw error when public key cannot be found', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, exampleResolvedDID);
            const request = yield auth.signAuthenticationRequest(authenticationRequest);
            try {
                const context = yield auth.verifyAuthenticationRequest(request);
                fail('Auth did not throw');
                console.log(context);
            }
            catch (err) {
                expect(err).toBeDefined();
            }
        }));
        it('should throw error when signing DID does not match issuer', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            authenticationRequest.iss = 'did:test:wrongdid';
            const token = new lib_1.JwsToken(authenticationRequest, registry);
            const request = yield token.sign(hubkey);
            try {
                const context = yield auth.verifyAuthenticationRequest(request);
                fail('Auth did not throw');
                console.log(context);
            }
            catch (err) {
                expect(err).toBeDefined();
            }
        }));
        it('should verify the signed authentication request with request as string', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            const request = yield auth.signAuthenticationRequest(authenticationRequest);
            const context = yield auth.verifyAuthenticationRequest(request);
            expect(context).toEqual(authenticationRequest);
        }));
        it('should verify the signed authentication request with request as buffer', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            const request = yield auth.signAuthenticationRequest(authenticationRequest);
            const requestBuffer = Buffer.from(request);
            const context = yield auth.verifyAuthenticationRequest(requestBuffer);
            expect(context).toEqual(authenticationRequest);
        }));
    });
    describe('formAuthenticationResponse', () => {
        it('should form Authenticaiton Request from Authentication Response', (done) => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            const response = yield auth.formAuthenticationResponse(authenticationRequest, hubDID, { key: 'hello' });
            const jws = new lib_1.JwsToken(response, registry);
            const payload = yield jws.verifySignature(hubPublicKey);
            const payloadObj = JSON.parse(payload);
            expect(payloadObj.iss).toEqual('https://self-issued.me');
            expect(payloadObj.sub).toBeDefined();
            expect(payloadObj.aud).toEqual('https://example.com/endpoint/8377464');
            expect(payloadObj.nonce).toEqual('123456789');
            expect(payloadObj.sub_jwk).toEqual(hubPublicKey);
            expect(payloadObj.did).toEqual(hubDID);
            expect(payloadObj.iat).toBeDefined();
            expect(payloadObj.exp).toBeDefined();
            done();
        }));
        it('should form Authenticaiton Request from Authentication Response with expiration', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            const response = yield auth.formAuthenticationResponse(authenticationRequest, hubDID, { key: 'hello' }, new Date());
            const jws = new lib_1.JwsToken(response, registry);
            const payload = yield jws.verifySignature(hubPublicKey);
            const payloadObj = JSON.parse(payload);
            expect(payloadObj.iss).toEqual('https://self-issued.me');
            expect(payloadObj.sub).toBeDefined();
            expect(payloadObj.aud).toEqual('https://example.com/endpoint/8377464');
            expect(payloadObj.nonce).toEqual('123456789');
            expect(payloadObj.sub_jwk).toEqual(hubPublicKey);
            expect(payloadObj.did).toEqual(hubDID);
            expect(payloadObj.iat).toBeDefined();
            expect(payloadObj.exp).toBeDefined();
        }));
        it('should throw error because could not find a key for responseDid', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            try {
                const response = yield auth.formAuthenticationResponse(authenticationRequest, exampleDID, { key: 'hello' });
                fail('Auth did not throw');
                console.log(response);
            }
            catch (err) {
                expect(err).toBeDefined();
            }
        }));
    });
    describe('verifyAuthenticationResponse', () => __awaiter(void 0, void 0, void 0, function* () {
        it('should verify an authentication response', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            const response = yield auth.formAuthenticationResponse(authenticationRequest, hubDID, { key: 'hello' });
            const payloadObj = yield auth.verifyAuthenticationResponse(response);
            expect(payloadObj.iss).toEqual('https://self-issued.me');
            expect(payloadObj.sub).toBeDefined();
            expect(payloadObj.aud).toEqual('https://example.com/endpoint/8377464');
            expect(payloadObj.nonce).toEqual('123456789');
            expect(payloadObj.sub_jwk).toEqual(hubPublicKey);
            expect(payloadObj.did).toEqual(hubDID);
            expect(payloadObj.iat).toBeDefined();
            expect(payloadObj.exp).toBeDefined();
        }));
        it('should verify an authentication response', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            const response = yield auth.formAuthenticationResponse(authenticationRequest, hubDID, { key: 'hello' });
            const responseBuffer = Buffer.from(response);
            const payloadObj = yield auth.verifyAuthenticationResponse(responseBuffer);
            expect(payloadObj.iss).toEqual('https://self-issued.me');
            expect(payloadObj.sub).toBeDefined();
            expect(payloadObj.aud).toEqual('https://example.com/endpoint/8377464');
            expect(payloadObj.nonce).toEqual('123456789');
            expect(payloadObj.sub_jwk).toEqual(hubPublicKey);
            expect(payloadObj.did).toEqual(hubDID);
            expect(payloadObj.iat).toBeDefined();
            expect(payloadObj.exp).toBeDefined();
        }));
        it('should throw an error for signer does not match issuer', () => __awaiter(void 0, void 0, void 0, function* () {
            setResolve(hubDID, hubResolvedDID);
            const milliseconds = 1000;
            const expirationTimeOffsetInMinutes = 5;
            const expiration = new Date(Date.now() + milliseconds * 60 * expirationTimeOffsetInMinutes);
            const iat = Math.floor(Date.now() / milliseconds); // ms to seconds
            const authenticationResponse = {
                iss: 'https://self-issued.me',
                sub: 'did:test:wrongdid',
                aud: 'https://example.com/endpoint/8377464',
                nonce: '123456789',
                exp: Math.floor(expiration.getTime() / milliseconds),
                iat: iat,
                sub_jwk: hubPublicKey,
                did: 'did:test:wrongdid',
                state: ''
            };
            const token = new lib_1.JwsToken(authenticationResponse, registry);
            const request = yield token.sign(hubkey);
            try {
                const context = yield auth.verifyAuthenticationResponse(request);
                fail('Auth did not throw');
                console.log(context);
            }
            catch (err) {
                console.log(err);
                expect(err).toBeDefined();
            }
        }));
    }));
    describe('getVerifiedRequest', () => {
        it('should reject for hub keys it does not contain', () => __awaiter(void 0, void 0, void 0, function* () {
            const payload = {
                description: 'Authentication test'
            };
            const jwsToken = new lib_1.JwsToken(payload, registry);
            const data = yield jwsToken.sign(examplekey, header);
            const unknownKey = yield lib_1.PrivateKeyRsa.generatePrivateKey('did:example:totallyunknown#key');
            const jweToken = new lib_1.JweToken(data, registry);
            const request = yield jweToken.encrypt(unknownKey);
            try {
                const context = yield auth.getVerifiedRequest(request);
                fail('Auth did not throw.');
                console.log(context);
            }
            catch (err) {
                expect(err).toBeDefined();
            }
        }));
        it('should decrypt the request with passed in key', () => __awaiter(void 0, void 0, void 0, function* () {
            const payload = {
                'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
            };
            const jws = new lib_1.JwsToken(payload, registry);
            const data = yield jws.sign(examplekey, header);
            const jwe = new lib_1.JweToken(data, registry);
            const request = yield jwe.encrypt(hubPublicKey);
            // Set context for hub verification of authentication request
            const hubExamplekeys = {};
            hubExamplekeys[`did:example:did#key1`] = hubkey;
            const hubAuthentication = new lib_1.Authentication({
                resolver,
                keys: hubExamplekeys
            });
            const context = yield hubAuthentication.getVerifiedRequest(request);
            expect(context.request).toEqual(JSON.stringify(payload));
        }));
        it('should decrypt the request with a key by reference', () => __awaiter(void 0, void 0, void 0, function* () {
            const payload = {
                'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
            };
            const keyStore = new lib_2.KeyStoreMem();
            yield keyStore.save('key', examplekey);
            const data = yield keyStore.sign('key', JSON.stringify(payload), lib_2.ProtectionFormat.CompactJsonJws, registry, header);
            const jwe = new lib_1.JweToken(data, registry);
            const request = yield jwe.encrypt(hubPublicKey);
            const context = yield auth.getVerifiedRequest(request);
            expect(context.request).toEqual(JSON.stringify(payload));
        }));
        it('should return false if access token is wrong token sub', () => __awaiter(void 0, void 0, void 0, function* () {
            const examplekeys = {};
            examplekeys[`${exampleDID}#keys-1`] = examplekey;
            const keyStore = new lib_2.KeyStoreMem();
            yield keyStore.save('key', examplekey);
            const exampleAuth = new lib_1.Authentication({
                resolver,
                keyStore,
                keys: examplekeys
            });
            const jws = yield exampleAuth.createAccessToken('xxx', 'key', 10);
            const sub = yield exampleAuth.verifyJwt(examplekey, jws, exampleDID);
            expect(sub).toBe(false);
        }));
        it('should return a new access token', () => __awaiter(void 0, void 0, void 0, function* () {
            const exampleKeyStore = new lib_2.KeyStoreMem();
            yield exampleKeyStore.save('example', examplekey);
            const exampleAuth = new lib_1.Authentication({
                resolver,
                keyStore: exampleKeyStore,
                keyReferences: ['example']
            });
            const token = yield exampleAuth.issueNewAccessToken(exampleDID, '1234567890', 'example', hubPublicKey);
            const hubKeyStore = new lib_2.KeyStoreMem();
            yield hubKeyStore.save('hub', hubkey);
            const hubAuth = new lib_1.Authentication({
                resolver,
                keyStore: hubKeyStore,
                keyReferences: ['hub']
            });
            const data = yield hubAuth.getVerifiedRequest(token, true);
            expect(data).toBeDefined();
        }));
        it('should return false if access token is expired', () => __awaiter(void 0, void 0, void 0, function* () {
            const jws = yield registry.constructJws({
                sub: exampleDID,
                iat: new Date(Date.now()),
                exp: new Date(Date.now() - 5 * 60 * 1000)
            }).sign(examplekey);
            const examplekeys = {};
            examplekeys[`${exampleDID}#keys-1`] = examplekey;
            const exampleAuth = new lib_1.Authentication({
                resolver,
                keys: examplekeys
            });
            const exp = yield exampleAuth.verifyJwt(examplekey, jws, exampleDID);
            expect(exp).toBe(false);
        }));
        it('should return false if access token is mal formed', () => __awaiter(void 0, void 0, void 0, function* () {
            const jws = 'abcdef';
            const examplekeys = {};
            examplekeys[`${exampleDID}#keys-1`] = examplekey;
            const exampleAuth = new lib_1.Authentication({
                resolver,
                keys: examplekeys
            });
            const tokenFormat = yield exampleAuth.verifyJwt(examplekey, jws, exampleDID);
            expect(tokenFormat).toBe(false);
        }));
        it('should return false if payload is missing', () => __awaiter(void 0, void 0, void 0, function* () {
            const examplekeys = {};
            examplekeys[`${exampleDID}#keys-1`] = examplekey;
            const exampleAuth = new lib_1.Authentication({
                resolver,
                keys: examplekeys
            });
            const tokenFormat = yield exampleAuth.verifyJwt(examplekey, undefined, exampleDID);
            expect(tokenFormat).toBe(false);
        }));
        it('should throw if invalid signature', () => __awaiter(void 0, void 0, void 0, function* () {
            const payload = {
                'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
            };
            const jws = new lib_1.JwsToken(payload, registry);
            let data = yield jws.sign(examplekey, header);
            const index = data.lastIndexOf('.') + 1;
            const char = data[index] === 'a' ? 'b' : 'a';
            data = data.substr(0, index) + char + data.substr(index + 1);
            const jwe = new lib_1.JweToken(data, registry);
            const request = yield jwe.encrypt(hubPublicKey);
            try {
                yield auth.getVerifiedRequest(request);
                fail('Expected function to throw an Error.');
            }
            catch (err) {
                expect(err).toBeDefined();
            }
        }));
        it('should throw if the requester key is not found', () => __awaiter(void 0, void 0, void 0, function* () {
            const payload = {
                'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
            };
            const jws = new lib_1.JwsToken(payload, registry);
            const unknownPublicKey = yield lib_1.PrivateKeyRsa.generatePrivateKey(`${exampleDID}#unknown-key`);
            const data = yield jws.sign(unknownPublicKey);
            const jwe = new lib_1.JweToken(data, registry);
            const request = yield jwe.encrypt(hubPublicKey);
            try {
                yield auth.getVerifiedRequest(request);
                fail('Expected function to throw an Error.');
            }
            catch (err) {
                expect(err).toBeDefined();
            }
        }));
        it('should throw if the key is not understood', () => __awaiter(void 0, void 0, void 0, function* () {
            const payload = {
                'test-data': Math.round(Math.random() * Number.MAX_SAFE_INTEGER)
            };
            const jws = new lib_1.JwsToken(payload, registry);
            const data = yield jws.sign(examplekey, header);
            const jwe = new lib_1.JweToken(data, registry);
            const request = yield jwe.encrypt(hubPublicKey);
            resolver.setHandle(() => {
                return new Promise((resolve) => {
                    resolve(new did_common_typescript_1.DidDocument({
                        '@context': 'https://w3id.org/did/v1',
                        'id': hubDID,
                        'publicKey': [{
                                id: `${hubDID}#key1`,
                                type: 'ExplicitlyUnknownKeyType2018',
                                controller: hubDID,
                                publicKeyJwk: hubkey
                            }]
                    }));
                });
            });
            try {
                yield auth.getVerifiedRequest(request);
                fail('Expected function to throw an Error.');
            }
            catch (err) {
                expect(err).toBeDefined();
            }
        }));
    });
    describe('getAuthenticatedRequest', () => {
        it(`should encrypt with the DID's public key`, () => __awaiter(void 0, void 0, void 0, function* () {
            const content = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();
            const request = yield auth.getAuthenticatedRequest(content, exampleDID, yield newAccessToken(examplekey));
            const jwe = registry.constructJwe(request.toString());
            const jwsstring = yield jwe.decrypt(examplekey);
            const jws = registry.constructJws(jwsstring);
            expect(jws.getPayload()).toEqual(content);
        }));
    });
    describe('getAuthenticatedResponse', () => {
        it('should be understood by decrypt and validate. Key passed by value', () => __awaiter(void 0, void 0, void 0, function* () {
            const requestString = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();
            // Set context for client authentication request
            const clientExamplekeys = {};
            clientExamplekeys[`${exampleDID}#keys-1`] = examplekey;
            const clientAuth = new lib_1.Authentication({
                resolver,
                keys: clientExamplekeys
            });
            setResolve(hubDID, hubResolvedDID);
            // generate request for hub
            const request = yield clientAuth.getAuthenticatedRequest(requestString, hubDID, header['did-access-token']);
            // Set context for hub verification of authentication request
            const hubExamplekeys = {};
            hubExamplekeys[`did:example:did#key1`] = hubkey;
            const hubAuthentication = new lib_1.Authentication({
                resolver,
                keys: hubExamplekeys
            });
            setResolve(exampleDID, exampleResolvedDID);
            const verifiedRequest = yield hubAuthentication.getVerifiedRequest(request, true);
            if (verifiedRequest instanceof Buffer) {
                fail('Request should validate with the given access token');
                return;
            }
            // Setup hub response
            const testContent = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();
            const response = yield hubAuthentication.getAuthenticatedResponse(verifiedRequest, testContent);
            setResolve(hubDID, hubResolvedDID);
            // Client validates hub response
            const context = yield clientAuth.getVerifiedRequest(response, false);
            expect(context.request).toEqual(testContent);
        }));
        it('should be understood by decrypt and validate. Key passed by reference', () => __awaiter(void 0, void 0, void 0, function* () {
            const requestString = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();
            // Set context for client authentication request
            let clientKeyStore = new lib_2.KeyStoreMem();
            const clientKeyId = 'clientKey';
            yield clientKeyStore.save(clientKeyId, examplekey);
            const clientAuth = new lib_1.Authentication({
                resolver,
                keyStore: clientKeyStore,
                keyReferences: [clientKeyId]
            });
            setResolve(hubDID, hubResolvedDID);
            // generate request for hub
            const request = yield clientAuth.getAuthenticatedRequest(requestString, hubDID, header['did-access-token']);
            // Set context for hub verification of authentication request
            let hubKeyStore = new lib_2.KeyStoreMem();
            const hubKeyId = 'hubKey';
            yield hubKeyStore.save(hubKeyId, hubkey);
            const hubAuthentication = new lib_1.Authentication({
                resolver,
                keyStore: hubKeyStore,
                keyReferences: [hubKeyId]
            });
            setResolve(exampleDID, exampleResolvedDID);
            const verifiedRequest = yield hubAuthentication.getVerifiedRequest(request, true);
            if (verifiedRequest instanceof Buffer) {
                fail('Request should validate with the given access token');
                return;
            }
            // Setup hub response
            const testContent = Math.round(Math.random() * Number.MAX_SAFE_INTEGER).toString();
            const response = yield hubAuthentication.getAuthenticatedResponse(verifiedRequest, testContent);
            setResolve(hubDID, hubResolvedDID);
            // Client validates hub response
            const context = yield clientAuth.getVerifiedRequest(response, false);
            expect(context.request).toEqual(testContent);
        }));
    });
});
//# sourceMappingURL=Authentication.spec.js.map