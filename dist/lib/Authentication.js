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
const did_common_typescript_1 = require("@decentralized-identity/did-common-typescript");
const Constants_1 = __importDefault(require("./Constants"));
const PublicKey_1 = __importDefault(require("./security/PublicKey"));
const CryptoFactory_1 = __importDefault(require("./CryptoFactory"));
const RsaCryptoSuite_1 = require("./crypto/rsa/RsaCryptoSuite");
const Secp256k1CryptoSuite_1 = require("./crypto/ec/Secp256k1CryptoSuite");
const JwsToken_1 = __importDefault(require("./security/JwsToken"));
const v4_1 = __importDefault(require("uuid/v4"));
const AesCryptoSuite_1 = __importDefault(require("./crypto/aes/AesCryptoSuite"));
const KeyStoreMem_1 = __importDefault(require("./keyStore/KeyStoreMem"));
const ProtectionFormat_1 = require("./keyStore/ProtectionFormat");
/**
 * Class for decrypting and verifying, or signing and encrypting content in an End to End DID Authentication format
 */
class Authentication {
    /**
     * Authentication constructor
     * @param options Arguments to a constructor in a named object
     */
    constructor(options) {
        this.resolver = options.resolver;
        this.tokenValidDurationInMinutes = options.tokenValidDurationInMinutes || Constants_1.default.defaultTokenDurationInMinutes;
        if (options.keyStore) {
            this.keyStore = options.keyStore;
        }
        else {
            this.keyStore = new KeyStoreMem_1.default();
        }
        this.keys = options.keys;
        this.keyReferences = options.keyReferences;
        if (!this.keys && !this.keyReferences) {
            throw new Error(`A key by reference (keyReferences) or a key by value (keys) is required`);
        }
        if (this.keys && this.keyReferences) {
            throw new Error(`Do not mix a key by reference (keyReferences) with a key by value (keys) is required`);
        }
        this.factory = new CryptoFactory_1.default(options.cryptoSuites || [new AesCryptoSuite_1.default(), new RsaCryptoSuite_1.RsaCryptoSuite(), new Secp256k1CryptoSuite_1.Secp256k1CryptoSuite()]);
    }
    /**
     * Signs the AuthenticationRequest with the private key of the Requester and returns the signed JWT.
     * @param request well-formed AuthenticationRequest object
     * @returns the signed compact JWT.
     */
    signAuthenticationRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            if (request.response_type !== 'id_token' || request.scope !== 'openid') {
                throw new Error('Authentication Request not formed correctly');
            }
            // Make sure the passed in key is stored in the key store
            let referenceToStoredKey;
            if (this.keyReferences) {
                // for signing always use last key
                referenceToStoredKey = this.keyReferences[this.keyReferences.length - 1];
            }
            else {
                referenceToStoredKey = yield this.getKeyReference(request.iss);
            }
            return this.keyStore.sign(referenceToStoredKey, JSON.stringify(request), ProtectionFormat_1.ProtectionFormat.CompactJsonJws, this.factory);
        });
    }
    /**
     * Verifies signature on request and returns AuthenticationRequest.
     * @param request Authentiation Request as a buffer or string.
     */
    verifyAuthenticationRequest(request) {
        return __awaiter(this, void 0, void 0, function* () {
            let jwsToken;
            if (request instanceof Buffer) {
                jwsToken = new JwsToken_1.default(request.toString(), this.factory);
            }
            else {
                jwsToken = new JwsToken_1.default(request, this.factory);
            }
            const keyId = jwsToken.getHeader().kid;
            const keyDid = did_common_typescript_1.DidDocument.getDidFromKeyId(keyId);
            const content = yield this.verifySignature(jwsToken);
            const verifiedRequest = JSON.parse(content);
            if (verifiedRequest.iss !== keyDid) {
                throw new Error('Signing DID does not match issuer');
            }
            return verifiedRequest;
        });
    }
    /**
     * Given a challenge, forms a signed response using a given DID that expires at expiration, or a default expiration.
     * @param authRequest Challenge to respond to
     * @param responseDid The DID to respond with
     * @param claims Claims that the requester asked for
     * @param expiration optional expiration datetime of the response
     * @param keyReference pointing to the signing key
     */
    formAuthenticationResponse(authRequest, responseDid, claims, expiration) {
        return __awaiter(this, void 0, void 0, function* () {
            const referenceToStoredKey = yield this.getKeyReference(responseDid);
            const publicKey = yield this.keyStore.get(referenceToStoredKey, true);
            const base64UrlThumbprint = yield PublicKey_1.default.getThumbprint(publicKey);
            // milliseconds to seconds
            const milliseconds = 1000;
            if (!expiration) {
                const expirationTimeOffsetInMinutes = 5;
                expiration = new Date(Date.now() + milliseconds * 60 * expirationTimeOffsetInMinutes); // 5 minutes from now
            }
            const iat = Math.floor(Date.now() / milliseconds); // ms to seconds
            let response = {
                iss: 'https://self-issued.me',
                sub: base64UrlThumbprint,
                aud: authRequest.client_id,
                nonce: authRequest.nonce,
                exp: Math.floor(expiration.getTime() / milliseconds),
                iat,
                sub_jwk: publicKey,
                did: responseDid,
                state: authRequest.state
            };
            response = Object.assign(response, claims);
            return this.keyStore.sign(referenceToStoredKey, JSON.stringify(response), ProtectionFormat_1.ProtectionFormat.CompactJsonJws, this.factory, {
                iat: iat.toString(),
                exp: Math.floor(expiration.getTime() / milliseconds).toString()
            });
        });
    }
    /**
     * Return a reference to the private key that was passed by caller.
     * If the key was passed in by value, it will be stored in the store and a reference is returned
     * @param iss Issuer identifier
     */
    getKeyReference(iss) {
        return __awaiter(this, void 0, void 0, function* () {
            let referenceToStoredKey;
            if (this.keys) {
                const key = this.getKey(iss);
                if (!key) {
                    throw new Error(`Could not find a key for ${iss}`);
                }
                referenceToStoredKey = key.kid;
                yield this.keyStore.save(referenceToStoredKey, key);
            }
            else {
                throw new Error(`No private keys passed`);
            }
            return referenceToStoredKey;
        });
    }
    /**
     * Private method that gets the private key of the DID from the key mapping.
     * @param did the DID whose private key is used to sign JWT.
     * @returns private key of the DID.
     */
    getKey(did) {
        let key;
        for (const keyId in this.keys) {
            if (keyId.startsWith(did)) {
                key = this.keys[keyId];
                break;
            }
        }
        return key;
    }
    /**
     * helper method that verifies the signature on jws and returns the payload if signature is verified.
     * @param jwsToken signed jws token whose signature will be verified.
     * @returns the payload if jws signature is verified.
     */
    verifySignature(jwsToken) {
        return __awaiter(this, void 0, void 0, function* () {
            const keyId = jwsToken.getHeader().kid;
            const keyDid = did_common_typescript_1.DidDocument.getDidFromKeyId(keyId);
            const results = yield this.resolver.resolve(keyDid);
            const didPublicKey = results.didDocument.getPublicKey(keyId);
            if (!didPublicKey) {
                throw new Error('Could not find public key');
            }
            const publicKey = this.factory.constructPublicKey(didPublicKey);
            return jwsToken.verifySignature(publicKey);
        });
    }
    /**
     * Verifies the signature on a AuthenticationResponse and returns a AuthenticationResponse object
     * @param authResponse AuthenticationResponse to verify as a string or buffer
     * @returns the authenticationResponse as a AuthenticationResponse Object
     */
    verifyAuthenticationResponse(authResponse) {
        return __awaiter(this, void 0, void 0, function* () {
            const clockSkew = 5 * 60 * 1000; // 5 minutes
            let jwsToken;
            if (authResponse instanceof Buffer) {
                jwsToken = new JwsToken_1.default(authResponse.toString(), this.factory);
            }
            else {
                jwsToken = new JwsToken_1.default(authResponse, this.factory);
            }
            const exp = jwsToken.getHeader().exp;
            if (exp) {
                if (exp * 1000 + clockSkew < Date.now()) {
                    throw new Error('Response expired');
                }
            }
            const keyId = jwsToken.getHeader().kid;
            const keyDid = did_common_typescript_1.DidDocument.getDidFromKeyId(keyId);
            const content = yield this.verifySignature(jwsToken);
            const response = JSON.parse(content);
            if (response.did !== keyDid) {
                throw new Error('Signing DID does not match issuer');
            }
            return response;
        });
    }
    /**
     * Given a JOSE Authenticated Request, will decrypt the request, resolve the requester's did, and validate the signature.
     * @param request The JOSE Authenticated Request to decrypt and validate
     * @param accessTokenCheck Check the validity of the access token
     * @returns The content of the request as a VerifiedRequest, or a response containing an access token
     */
    getVerifiedRequest(request, accessTokenCheck = true) {
        return __awaiter(this, void 0, void 0, function* () {
            // Load the key specified by 'kid' in the JWE header.
            const requestString = request.toString();
            const jweToken = this.factory.constructJwe(requestString);
            const keyReference = yield this.getPrivateKeyForJwe(jweToken);
            const jwsString = yield this.keyStore.decrypt(keyReference, requestString, ProtectionFormat_1.ProtectionFormat.CompactJsonJwe, this.factory);
            const jwsToken = this.factory.constructJws(jwsString);
            // getting metadata for the request
            const jwsHeader = jwsToken.getHeader();
            const requestKid = jwsHeader.kid;
            const requester = did_common_typescript_1.DidDocument.getDidFromKeyId(requestKid);
            const requesterKey = yield this.getPublicKey(jwsToken);
            const nonce = this.getRequesterNonce(jwsToken);
            // Get the public key for validation
            const localPublicKey = yield this.keyStore.get(keyReference, true);
            if (accessTokenCheck) {
                // verify access token
                const accessTokenString = jwsHeader['did-access-token'];
                if (!accessTokenString) {
                    // no access token was given, this should be a seperate endpoint request
                    return this.issueNewAccessToken(requester, nonce, keyReference, requesterKey);
                }
                if (!(yield this.verifyJwt(localPublicKey, accessTokenString, requester))) {
                    throw new Error('Invalid access token');
                }
            }
            const plaintext = yield jwsToken.verifySignature(requesterKey);
            return {
                localKeyId: localPublicKey.kid,
                requesterPublicKey: requesterKey,
                nonce,
                request: plaintext
            };
        });
    }
    /**
     * Given the verified request, uses the same keys and metadata to sign and encrypt the response
     * @param request The original JOSE Verified Request request
     * @param response The plaintext response to be signed and encrypted
     * @returns An encrypted and signed form of the response
     */
    getAuthenticatedResponse(request, response) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.signThenEncryptInternal(request.nonce, request.requesterPublicKey, response);
        });
    }
    /**
     * Creates an encrypted and authenticated JOSE request
     * @param content the content of the request
     * @param privateKey the private key to sign with
     * @param recipient the DID the request is indended for
     * @param accessToken an access token to be used with the other party
     */
    getAuthenticatedRequest(content, recipient, accessToken) {
        return __awaiter(this, void 0, void 0, function* () {
            const requesterNonce = v4_1.default();
            const result = yield this.resolver.resolve(recipient);
            const document = result.didDocument;
            if (!document.publicKey) {
                throw new Error(`Could not find public keys for ${recipient}`);
            }
            // perhaps a more intellegent key choosing algorithm could be implemented here
            // TODO get the key based on kid
            const documentKey = document.publicKey[0];
            const publicKey = this.factory.constructPublicKey(documentKey);
            return this.signThenEncryptInternal(requesterNonce, publicKey, content, accessToken);
        });
    }
    /**
     * Given a JWE, retrieves the PrivateKey to be used for decryption
     * @param jweToken The JWE to inspect
     * @returns The PrivateKey corresponding to the JWE's encryption
     */
    getPrivateKeyForJwe(jweToken) {
        return __awaiter(this, void 0, void 0, function* () {
            const keyId = jweToken.getHeader().kid;
            if (this.keys) {
                const key = this.keys[keyId];
                if (!key) {
                    throw new Error(`Unable to decrypt request; encryption key '${keyId}' not found`);
                }
                yield this.keyStore.save(keyId, key);
                return keyId;
            }
            else {
                if (!this.keyReferences) {
                    throw new Error(`Missing key reference for decrypting jwe`);
                }
                const allKeys = yield this.keyStore.list();
                let keyReferences = this.keyReferences.filter((reference) => allKeys[reference] && allKeys[reference] === keyId);
                if (!keyReferences) {
                    throw new Error(`Key reference for decrypting jwe not found`);
                }
                return keyReferences[0];
            }
        });
    }
    /**
     * Retrieves the PublicKey used to sign a JWS
     * @param request the JWE string
     * @returns The PublicKey the JWS used for signing
     */
    getPublicKey(jwsToken) {
        return __awaiter(this, void 0, void 0, function* () {
            const jwsHeader = jwsToken.getHeader();
            const requestKid = jwsHeader.kid;
            const requester = did_common_typescript_1.DidDocument.getDidFromKeyId(requestKid);
            // get the Public Key
            const result = yield this.resolver.resolve(requester);
            const document = result.didDocument;
            const documentKey = document.getPublicKey(requestKid);
            if (!documentKey) {
                throw new Error(`Unable to verify request; signature key ${requestKid} not found`);
            }
            return this.factory.constructPublicKey(documentKey);
        });
    }
    /**
     * Retrieves the nonce from the JWS
     * @param jwsToken The JWS containing the nonce
     * @returns The nonce
     */
    getRequesterNonce(jwsToken) {
        return jwsToken.getHeader()['did-requester-nonce'];
    }
    /**
     * Forms a JWS using the local private key and content, then wraps in JWE using the requesterKey and nonce.
     * @param nonce Nonce to be included in the response
     * @param requesterkey PublicKey in which to encrypt the response
     * @param content The content to be signed and encrypted
     * @returns An encrypted and signed form of the content
     */
    signThenEncryptInternal(nonce, requesterkey, content, accesstoken) {
        return __awaiter(this, void 0, void 0, function* () {
            const jwsHeaderParameters = { 'did-requester-nonce': nonce };
            if (accesstoken) {
                jwsHeaderParameters['did-access-token'] = accesstoken;
            }
            // Make sure the passed in key is stored in the key store
            let referenceToStoredKey;
            if (this.keyReferences) {
                // for signing always use last key
                referenceToStoredKey = this.keyReferences[this.keyReferences.length - 1];
            }
            else {
                if (!this.keys) {
                    throw new Error(`No private keys passed into Authentication`);
                }
                // Assumption, the last added property is the last and more recent key
                const kid = Object.keys(this.keys)[Object.keys(this.keys).length - 1];
                referenceToStoredKey = yield this.getKeyReference(kid);
            }
            const jwsCompactString = yield this.keyStore.sign(referenceToStoredKey, content, ProtectionFormat_1.ProtectionFormat.CompactJsonJws, this.factory, jwsHeaderParameters);
            const jweToken = this.factory.constructJwe(jwsCompactString);
            return jweToken.encrypt(requesterkey);
        });
    }
    /**
     * Creates a new access token and wrap it in a JWE/JWS pair.
     * @param subjectDid the DID this access token is issue to
     * @param nonce the nonce used in the original request
     * @param issuerKeyReference A reference to the key used in the original request
     * @param requesterKey the requesters key to encrypt the response with
     * @returns A new access token
     */
    issueNewAccessToken(subjectDid, nonce, issuerKeyReference, requesterKey) {
        return __awaiter(this, void 0, void 0, function* () {
            // Create a new access token.
            const accessToken = yield this.createAccessToken(subjectDid, issuerKeyReference, this.tokenValidDurationInMinutes);
            // Sign then encrypt the new access token.
            return this.signThenEncryptInternal(nonce, requesterKey, accessToken);
        });
    }
    /**
     * Creates an access token for the subjectDid using the privateKey for the validDurationInMinutes
     * @param subjectDid The did this access token is issued to
     * @param privateKeyReference The private key used to generate this access token
     * @param validDurationInMinutes The duration this token is valid for, in minutes
     * @returns Signed JWT in compact serialized format.
     */
    createAccessToken(subjectDid, privateKeyReference, validDurationInMinutes) {
        return __awaiter(this, void 0, void 0, function* () {
            const payload = this.factory.constructJws({
                sub: subjectDid,
                iat: new Date(Date.now()),
                exp: new Date(Date.now() + validDurationInMinutes * 60 * 1000)
            });
            return this.keyStore.sign(privateKeyReference, payload.content, ProtectionFormat_1.ProtectionFormat.CompactJsonJws, this.factory);
        });
    }
    /**
     * Verifies:
     * 1. JWT signature.
     * 2. Token's subject matches the given requeter DID.
     * 3. Token is not expired.
     *
     * @param publicKey Public key used to verify the given JWT in JWK JSON object format.
     * @param signedJwtString The signed-JWT string.
     * @param expectedRequesterDid Expected requester ID in the 'sub' field of the JWT payload.
     * @returns true if token passes all validation, false otherwise.
     */
    verifyJwt(publicKey, signedJwtString, expectedRequesterDid) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!publicKey || !signedJwtString || !expectedRequesterDid) {
                return false;
            }
            try {
                const jwsToken = this.factory.constructJws(signedJwtString);
                const verifiedData = yield jwsToken.verifySignature(publicKey);
                // Verify that the token was issued to the same person making the current request.
                const token = JSON.parse(verifiedData);
                if (token.sub !== expectedRequesterDid) {
                    return false;
                }
                // Verify that the token is not expired.
                const now = new Date(Date.now());
                const expiry = new Date(token.exp);
                if (now > expiry) {
                    return false;
                }
                return true;
            }
            catch (_a) {
                return false;
            }
        });
    }
}
exports.default = Authentication;
//# sourceMappingURL=Authentication.js.map