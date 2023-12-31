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
const Base64Url_1 = __importDefault(require("../utilities/Base64Url"));
const JoseToken_1 = __importDefault(require("./JoseToken"));
/**
 * Class for performing JWE encryption operations.
 * This class hides the JOSE and crypto library dependencies to allow support for additional crypto algorithms.
 */
class JweToken extends JoseToken_1.default {
    constructor(content, cryptoFactory) {
        super(content, cryptoFactory);
        this.cryptoFactory = cryptoFactory;
        let jsonContent = content;
        // check for compact JWE
        if (typeof content === 'string') {
            // 1. Parse JWE for components: BASE64URL(UTF8(JWE Header)) || '.' || BASE64URL(JWE Encrypted Key) || '.' ||
            //    BASE64URL(JWE Initialization Vector) || '.' || BASE64URL(JWE Ciphertext) || '.' ||
            //    BASE64URL(JWE Authentication Tag)
            const base64EncodedValues = content.split('.');
            if (base64EncodedValues.length === 5) {
                // 2. Base64url decode the encoded header, encryption key, iv, ciphertext, and auth tag
                this.protectedHeaders = base64EncodedValues[0];
                this.encryptedKey = Base64Url_1.default.decodeToBuffer(base64EncodedValues[1]);
                this.iv = Base64Url_1.default.decodeToBuffer(base64EncodedValues[2]);
                this.payload = base64EncodedValues[3];
                this.tag = Base64Url_1.default.decodeToBuffer(base64EncodedValues[4]);
                // 15. Let the Additional Authentication Data (AAD) be ASCII(encodedprotectedHeader)
                this.aad = Buffer.from(base64EncodedValues[0]);
                return;
            }
            // attempt to parse the string into a JSON object in the event it is a JSON serialized token
            try {
                jsonContent = JSON.parse(content);
            }
            catch (error) {
                // it was not.
            }
        }
        if (typeof jsonContent === 'object' &&
            'ciphertext' in jsonContent && typeof jsonContent.ciphertext === 'string' &&
            'iv' in jsonContent && typeof jsonContent.iv === 'string' &&
            'tag' in jsonContent && typeof jsonContent.tag === 'string' &&
            ('protected' in jsonContent || 'unprotected' in jsonContent || 'header' in jsonContent)) {
            if (('protected' in jsonContent && jsonContent.protected !== undefined && typeof jsonContent.protected !== 'string') ||
                ('unprotected' in jsonContent && jsonContent.unprotected !== undefined && typeof jsonContent.unprotected !== 'object') ||
                ('header' in jsonContent && jsonContent.header !== undefined && typeof jsonContent.header !== 'object')) {
                // One of the properties is of the wrong type
                return;
            }
            if ('recipients' in jsonContent) {
                // TODO: General JWE JSON Serialization (Issue #22)
                return;
            }
            else if ('encrypted_key' in jsonContent && typeof jsonContent.encrypted_key === 'string') {
                // Flattened JWE JSON Serialization
                if ('header' in jsonContent) {
                    this.unprotectedHeaders = jsonContent.header;
                }
                this.encryptedKey = Base64Url_1.default.decodeToBuffer(jsonContent.encrypted_key);
            }
            else {
                // This isn't a JWE
                return;
            }
            if ('protected' in jsonContent) {
                this.protectedHeaders = jsonContent.protected;
            }
            if ('unprotected' in jsonContent) {
                if (this.unprotectedHeaders) {
                    this.unprotectedHeaders = Object.assign(this.unprotectedHeaders, jsonContent.unprotected);
                }
                else {
                    this.unprotectedHeaders = jsonContent.unprotected;
                }
            }
            this.iv = Base64Url_1.default.decodeToBuffer(jsonContent.iv);
            this.tag = Base64Url_1.default.decodeToBuffer(jsonContent.tag);
            this.payload = jsonContent.ciphertext;
            if (jsonContent.aad) {
                this.aad = Buffer.from(this.protectedHeaders + '.' + jsonContent.aad);
            }
            else {
                this.aad = Buffer.from(this.protectedHeaders || '');
            }
        }
    }
    /**
     * Encrypts the original content from construction into a JWE compact serialized format
     * using the given key in JWK JSON object format.Content encryption algorithm is hardcoded to 'A128GCM'.
     *
     * @returns Buffer of the original content encrypted in JWE compact serialized format.
     */
    encrypt(jwk, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
            // Decide key encryption algorithm based on given JWK.
            const keyEncryptionAlgorithm = jwk.defaultEncryptionAlgorithm;
            // Construct header.
            const enc = this.cryptoFactory.getDefaultSymmetricEncryptionAlgorithm();
            let header = Object.assign({}, {
                kid: jwk.kid,
                alg: keyEncryptionAlgorithm,
                enc
            }, additionalHeaders);
            // Base64url encode header.
            const protectedHeaderBase64Url = Base64Url_1.default.encode(JSON.stringify(header));
            // Get the symmetric encrypter and encrypt
            const symEncrypter = this.cryptoFactory.getSymmetricEncrypter(header.enc);
            const symEnc = yield symEncrypter.encrypt(Buffer.from(this.content), Buffer.from(protectedHeaderBase64Url));
            // Encrypt content encryption key then base64-url encode it.
            const encryptedKeyBuffer = yield this.encryptContentEncryptionKey(header.alg, symEnc.key, jwk);
            const encryptedKeyBase64Url = Base64Url_1.default.encode(encryptedKeyBuffer);
            // Get the base64s of the symmetric encryptions
            const initializationVectorBase64Url = Base64Url_1.default.encode(symEnc.initializationVector);
            const ciphertextBase64Url = Base64Url_1.default.encode(symEnc.ciphertext);
            const authenticationTagBase64Url = Base64Url_1.default.encode(symEnc.tag);
            // Form final compact serialized JWE string.
            const jweString = [
                protectedHeaderBase64Url,
                encryptedKeyBase64Url,
                initializationVectorBase64Url,
                ciphertextBase64Url,
                authenticationTagBase64Url
            ].join('.');
            return Buffer.from(jweString);
        });
    }
    /**
     * Encrypts the original content from construction into a JWE JSON serialized format using
     * the given key in JWK JSON object format. Content encryption algorithm is hardcoded to 'A128GCM'.
     *
     * @returns Buffer of the original content encrytped in JWE flattened JSON serialized format.
     */
    encryptAsFlattenedJson(jwk, options) {
        return __awaiter(this, void 0, void 0, function* () {
            // Decide key encryption algorithm based on given JWK.
            const keyEncryptionAlgorithm = jwk.defaultEncryptionAlgorithm;
            // Construct header.
            let header = Object.assign({}, {
                kid: jwk.kid,
                alg: keyEncryptionAlgorithm,
                enc: this.cryptoFactory.getDefaultSymmetricEncryptionAlgorithm()
            }, (options || {}).protected || {});
            // Base64url encode header.
            const protectedHeaderBase64Url = Base64Url_1.default.encode(JSON.stringify(header));
            const aad = Buffer.from(options && options.aad ? `${protectedHeaderBase64Url}.${Base64Url_1.default.encode(options.aad)}` : protectedHeaderBase64Url);
            // Symmetrically encrypt the content
            const symEncrypter = this.cryptoFactory.getSymmetricEncrypter(header.enc);
            const symEncParams = yield symEncrypter.encrypt(Buffer.from(this.content), aad);
            // Encrypt content encryption key and base64 all the parameters
            const encryptedKeyBuffer = yield this.encryptContentEncryptionKey(keyEncryptionAlgorithm, symEncParams.key, jwk);
            const encryptedKeyBase64Url = Base64Url_1.default.encode(encryptedKeyBuffer);
            const initializationVectorBase64Url = Base64Url_1.default.encode(symEncParams.initializationVector);
            const ciphertextBase64Url = Base64Url_1.default.encode(symEncParams.ciphertext);
            const authenticationTagBase64Url = Base64Url_1.default.encode(symEncParams.tag);
            // Form final compact serialized JWE string.
            let returnJwe = {
                protected: protectedHeaderBase64Url,
                unprotected: (options || {}).unprotected,
                encrypted_key: encryptedKeyBase64Url,
                iv: initializationVectorBase64Url,
                ciphertext: ciphertextBase64Url,
                tag: authenticationTagBase64Url
            };
            if (options && options.aad) {
                returnJwe.aad = Base64Url_1.default.encode(options.aad);
            }
            return returnJwe;
        });
    }
    /**
     * Encrypts the given content encryption key using the specified algorithm and asymmetric public key.
     *
     * @param keyEncryptionAlgorithm Asymmetric encryption algorithm to be used.
     * @param keyBuffer The content encryption key to be encrypted.
     * @param jwk The asymmetric public key used to encrypt the content encryption key.
     */
    encryptContentEncryptionKey(keyEncryptionAlgorithm, keyBuffer, jwk) {
        return __awaiter(this, void 0, void 0, function* () {
            let encrypt;
            let encrypter = this.cryptoFactory.getEncrypter(keyEncryptionAlgorithm);
            // Find the correct encryption algorithm from all cryptoAlgorithm plugins.
            if (encrypter) {
                encrypt = encrypter.encrypt;
            }
            else {
                const err = new Error(`Unsupported encryption algorithm: ${keyEncryptionAlgorithm}`);
                throw err;
            }
            return encrypt(keyBuffer, jwk);
        });
    }
    /**
     * Decrypts the original JWE using the given key in JWK JSON object format.
     *
     * @returns Decrypted plaintext of the JWE
     */
    decrypt(jwk) {
        return __awaiter(this, void 0, void 0, function* () {
            // following steps for JWE Decryption in RFC7516 section 5.2
            if (this.encryptedKey === undefined || this.payload === undefined || this.iv === undefined || this.aad === undefined || this.tag === undefined) {
                throw new Error('Could not parse contents into a JWE');
            }
            const ciphertext = Base64Url_1.default.decodeToBuffer(this.payload);
            const headers = this.getHeader();
            // 4. only applies to JWE JSON Serializaiton
            // 5. verify header fields
            ['alg', 'enc'].forEach((header) => {
                if (!(header in headers)) {
                    throw new Error(`Missing required header: ${header}`);
                }
            });
            if ('crit' in headers) { // RFC7516 4.1.13/RFC7515 4.1.11
                const extensions = headers.crit;
                if (extensions.filter) {
                    // TODO: determine which additional header fields are supported
                    const supported = [];
                    const unsupported = extensions.filter((extension) => { return !(extension in supported); });
                    if (unsupported.length > 0) {
                        throw new Error(`Unsupported "crit" headers: ${unsupported.join(', ')}`);
                    }
                }
                else {
                    throw new Error('Malformed "crit" header field');
                }
            }
            // 6. Determine the Key management mode by the "alg" header
            // TODO: Support other methods beyond key wrapping
            // 7. Verify that the JWE key is known
            if (headers.kid && jwk.kid && headers.kid !== jwk.kid) {
                throw new Error('JWEToken key does not match provided jwk key');
            }
            // 8. With keywrapping or direct key, let the jwk.kid be used to decrypt the encryptedkey
            // 9. Unwrap the encryptedkey to produce the content encryption key (CEK)
            const cek = yield (this.cryptoFactory.getEncrypter(headers.alg)).decrypt(this.encryptedKey, jwk);
            // TODO: Verify CEK length meets "enc" algorithm's requirement
            // 10. TODO: Support direct key, then ensure encryptedKey === ""
            // 11. TODO: Support direct encryption, let CEK be the shared symmetric key
            // 12. record successful CEK for this recipient or not
            // 13. Skip due to JWE JSON Serialization format specific
            // 14. Compute the protected header: BASE64URL(UTF8(JWE Header))
            // this would be base64Encodedvalues[0]
            // 16. Decrypt JWE Ciphertext using CEK, IV, AAD, and authTag, using "enc" algorithm.
            const symDecrypter = this.cryptoFactory.getSymmetricEncrypter(headers.enc);
            const plaintext = yield symDecrypter.decrypt(ciphertext, this.aad, this.iv, cek, this.tag);
            // 17. if a "zip" parameter was included, uncompress the plaintext using the specified algorithm
            if ('zip' in headers) {
                throw new Error('"zip" is not currently supported');
            }
            // 18. If there was no recipient, the JWE is invalid. Otherwise output the plaintext.
            return plaintext.toString('utf8');
        });
    }
    /**
     * Converts the JWE from the constructed type into a Compact JWE
     */
    toCompactJwe() {
        if (this.encryptedKey === undefined || this.payload === undefined || this.iv === undefined || this.aad === undefined || this.tag === undefined) {
            throw new Error('Could not parse contents into a JWE');
        }
        const protectedHeaders = this.getProtectedHeader();
        if (!('alg' in protectedHeaders) || !('enc' in protectedHeaders)) {
            throw new Error("'alg' and 'enc' are required to be in the protected header");
        }
        // Compact JWEs must have the default AAD value of the protected header (RFC 7516 5.1.14)
        if (this.aad.compare(Buffer.from(this.protectedHeaders || '')) !== 0) {
            throw new Error("'aad' must not be set in original JWE");
        }
        const encryptedKeyBase64Url = Base64Url_1.default.encode(this.encryptedKey);
        const initializationVectorBase64Url = Base64Url_1.default.encode(this.iv);
        const authenticationTagBase64Url = Base64Url_1.default.encode(this.tag);
        return `${this.protectedHeaders}.${encryptedKeyBase64Url}.${initializationVectorBase64Url}.${this.payload}.${authenticationTagBase64Url}`;
    }
    /**
     * Converts the JWE from the constructed type into a Flat JSON JWE
     * @param headers unprotected headers to use
     */
    toFlattenedJsonJwe(headers) {
        if (this.encryptedKey === undefined || this.payload === undefined || this.iv === undefined || this.aad === undefined || this.tag === undefined) {
            throw new Error('Could not parse contents into a JWE');
        }
        const unprotectedHeaders = headers || this.unprotectedHeaders || undefined;
        const protectedHeaders = this.getProtectedHeader();
        // TODO: verify no header parameters in unprotected headers conflict with protected headers
        if ((!('alg' in protectedHeaders) &&
            !(unprotectedHeaders && ('alg' in unprotectedHeaders))) || (!('enc' in protectedHeaders) &&
            !(unprotectedHeaders && ('enc' in unprotectedHeaders)))) {
            throw new Error("'alg' and 'enc' are required to be in the header or protected header");
        }
        const encryptedKeyBase64Url = Base64Url_1.default.encode(this.encryptedKey);
        const initializationVectorBase64Url = Base64Url_1.default.encode(this.iv);
        const authenticationTagBase64Url = Base64Url_1.default.encode(this.tag);
        let jwe = {
            encrypted_key: encryptedKeyBase64Url,
            iv: initializationVectorBase64Url,
            ciphertext: this.payload,
            tag: authenticationTagBase64Url
        };
        // add AAD if its unique
        if (this.aad.compare(Buffer.from(this.protectedHeaders || '')) !== 0) {
            // decrypt the aad and remove the protected headers.
            const aadParts = this.aad.toString().split('.');
            // Only the unique part of the aad is required
            jwe = Object.assign(jwe, { aad: aadParts[1] });
        }
        if (this.protectedHeaders) {
            jwe = Object.assign(jwe, { protected: this.protectedHeaders });
        }
        if (unprotectedHeaders) {
            jwe = Object.assign(jwe, { unprotected: unprotectedHeaders });
        }
        return jwe;
    }
}
exports.default = JweToken;
//# sourceMappingURL=JweToken.js.map