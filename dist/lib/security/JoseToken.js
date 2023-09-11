"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const Base64Url_1 = __importDefault(require("../utilities/Base64Url"));
/**
 * Base class for containing common operations for JWE and JWS tokens.
 * Not intended for creating instances of this class directly.
 */
class JoseToken {
    /**
     * Constructor for JoseToken that takes in a compact-serialized token string.
     */
    constructor(content, cryptoFactory) {
        this.cryptoFactory = cryptoFactory;
        if (typeof content === 'string') {
            this.content = content;
        }
        else {
            this.content = JSON.stringify(content);
        }
    }
    /**
     * Gets the header as a JS object.
     */
    getHeader() {
        let headers = this.unprotectedHeaders;
        if (!headers) {
            headers = {};
        }
        if (this.protectedHeaders) {
            headers = Object.assign(headers, this.getProtectedHeader());
        }
        return headers;
    }
    /**
     * Gets the protected headers as a JS object.
     */
    getProtectedHeader() {
        if (this.protectedHeaders) {
            const jsonString = Base64Url_1.default.decode(this.protectedHeaders);
            return JSON.parse(jsonString);
        }
        return {};
    }
    /**
     * Returns true if and only if the content was parsed as a token
     */
    isContentWellFormedToken() {
        return this.payload !== undefined;
    }
}
exports.default = JoseToken;
//# sourceMappingURL=JoseToken.js.map