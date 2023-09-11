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
const Protect_1 = __importDefault(require("./Protect"));
/**
 * Class defining methods and properties for a light KeyStore
 */
class KeyStoreMem {
    constructor() {
        this.store = new Map();
    }
    /**
     * Returns the key associated with the specified
     * key identifier.
     * @param keyReference for which to return the key.
     * @param publicKeyOnly True if only the public key is needed.
     */
    get(keyReference, publicKeyOnly) {
        return new Promise((resolve, reject) => {
            if (this.store.has(keyReference)) {
                const key = this.store.get(keyReference);
                if (publicKeyOnly) {
                    switch (key.kty.toLowerCase()) {
                        case 'ec':
                        case 'rsa':
                            return resolve(key.getPublicKey());
                        default:
                            throw new Error(`A secret does not has a public key`);
                    }
                }
                else {
                    resolve(key);
                }
            }
            else {
                reject(`${keyReference} not found`);
            }
        });
    }
    /**
     * Lists all keys with their corresponding key ids
     */
    list() {
        const dictionary = {};
        for (let [key, value] of this.store) {
            if (value.kid) {
                dictionary[key] = value.kid;
            }
        }
        return new Promise((resolve) => {
            resolve(dictionary);
        });
    }
    /**
     * Saves the specified key to the key store using
     * the key identifier.
     * @param keyIdentifier for the key being saved.
     * @param key being saved to the key store.
     */
    save(keyIdentifier, key) {
        console.log(this.store.toString() + keyIdentifier + key.toString());
        this.store.set(keyIdentifier, key);
        return new Promise((resolve) => {
            resolve();
        });
    }
    /**
     * Sign the data with the key referenced by keyIdentifier.
     * @param keyReference for the key used for signature.
     * @param payload Data to sign
     * @param format used to protect the content
     * @param cryptoFactory used to specify the algorithms to use
     * @param tokenHeaderParameters Header parameters in addition to 'alg' and 'kid' to be included in the header of the token.
     * @returns The protected message
     */
    sign(keyReference, payload, format, cryptoFactory, tokenHeaderParameters) {
        return __awaiter(this, void 0, void 0, function* () {
            return Protect_1.default.sign(keyReference, payload, format, this, cryptoFactory, tokenHeaderParameters);
        });
    }
    /**
     * Decrypt the data with the key referenced by keyReference.
     * @param keyReference Reference to the key used for signature.
     * @param cipher Data to decrypt
     * @param format Protection format used to decrypt the data
     * @param cryptoFactory used to specify the algorithms to use
     * @returns The plain text message
     */
    decrypt(keyReference, cipher, format, cryptoFactory) {
        return __awaiter(this, void 0, void 0, function* () {
            return Protect_1.default.decrypt(keyReference, cipher, format, this, cryptoFactory);
        });
    }
}
exports.default = KeyStoreMem;
//# sourceMappingURL=KeyStoreMem.js.map